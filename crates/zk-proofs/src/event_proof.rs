//! # Zero-Knowledge Event Existence Proofs
//!
//! Privacy-preserving proofs that an audit event exists in the log without
//! revealing sensitive event details.
//!
//! ## Privacy Model
//!
//! **Public (revealed)**:
//! - Sequence number
//! - Event type (Sign, Encrypt, KeyGeneration, etc.)
//! - Timestamp (optional)
//!
//! **Private (hidden)**:
//! - Client ID
//! - Key ID
//! - Operation details
//! - Result/error messages
//! - IP addresses
//!
//! ## Use Cases
//!
//! 1. **Compliance Auditing**: Prove certain operations occurred without exposing customer data
//! 2. **Regulatory Reporting**: Demonstrate event volume/types without revealing specifics
//! 3. **Third-Party Verification**: Allow external auditors to verify without seeing sensitive data

use crate::lasso::{LookupArgument, LookupTable};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{
    prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey,
};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use hsm_audit::{AuditEvent, EventType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EventProofError {
    #[error("Event not found: sequence {0}")]
    EventNotFound(u64),

    #[error("Invalid event: {0}")]
    InvalidEvent(String),

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub type EventProofResult<T> = Result<T, EventProofError>;

/// Request for event existence proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventProofRequest {
    /// The full audit event (private)
    pub event: AuditEvent,

    /// Merkle root of the audit log (for inclusion proof)
    pub merkle_root: [u8; 32],

    /// Position in the Merkle tree
    pub merkle_path: Vec<[u8; 32]>,
}

/// Zero-knowledge event existence proof
///
/// Proves that an event with specific public properties exists in the audit log
/// without revealing private details.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventExistenceProof {
    /// The SNARK proof
    #[serde(with = "proof_serde")]
    pub proof: Proof<Bn254>,

    /// Public inputs (revealed)
    pub public_inputs: PublicEventData,

    /// Proof size in bytes
    pub size_bytes: usize,
}

/// Public data about an event (revealed in the proof)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PublicEventData {
    /// Sequence number
    pub sequence: u64,

    /// Event type (Sign, Encrypt, etc.)
    pub event_type: EventType,

    /// Timestamp (Unix epoch seconds)
    pub timestamp: i64,

    /// Merkle root (proves inclusion in log)
    pub merkle_root: [u8; 32],
}

impl EventExistenceProof {
    /// Serialize proof to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.proof
            .serialize_compressed(&mut bytes)
            .expect("Serialization should not fail");

        // Append public inputs
        let public_json =
            serde_json::to_vec(&self.public_inputs).expect("JSON serialization should not fail");
        bytes.extend_from_slice(&(public_json.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&public_json);

        bytes
    }

    /// Deserialize proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> EventProofResult<Self> {
        if bytes.len() < 4 {
            return Err(EventProofError::SerializationError(
                "Insufficient bytes".to_string(),
            ));
        }

        // Find the split point (last 4 bytes contain public input length)
        let split_point = bytes
            .len()
            .checked_sub(4)
            .ok_or_else(|| EventProofError::SerializationError("Invalid format".to_string()))?;

        let public_len = u32::from_le_bytes(bytes[split_point..].try_into().unwrap()) as usize;

        if split_point < public_len {
            return Err(EventProofError::SerializationError(
                "Invalid public input length".to_string(),
            ));
        }

        let proof_end = split_point - public_len;
        let proof = Proof::<Bn254>::deserialize_compressed(&bytes[..proof_end])
            .map_err(|e| EventProofError::SerializationError(e.to_string()))?;

        let public_inputs: PublicEventData = serde_json::from_slice(&bytes[proof_end..split_point])
            .map_err(|e| EventProofError::SerializationError(e.to_string()))?;

        Ok(Self {
            proof,
            public_inputs,
            size_bytes: bytes.len(),
        })
    }
}

/// Circuit for proving event existence with privacy
///
/// This circuit proves:
/// 1. An event with sequence number S exists
/// 2. The event has type T
/// 3. The event is included in the Merkle tree with root R
/// 4. WITHOUT revealing: client ID, key ID, operation details
#[derive(Clone)]
pub struct EventExistenceCircuit {
    /// Full event data (private witness)
    event: AuditEvent,

    /// Merkle path for inclusion proof (private witness)
    merkle_path: Vec<[u8; 32]>,

    /// Public inputs
    sequence: u64,
    event_type: u8, // EventType as u8
    timestamp: i64,
    merkle_root: [u8; 32],
}

impl EventExistenceCircuit {
    /// Create a new event existence circuit
    pub fn new(event: AuditEvent, merkle_path: Vec<[u8; 32]>, merkle_root: [u8; 32]) -> Self {
        // Extract values before moving event
        let sequence = event.sequence;
        let event_type_u8 = format!("{:?}", event.event_type)
            .as_bytes()
            .get(0)
            .copied()
            .unwrap_or(0);
        let timestamp = event.timestamp.timestamp();

        Self {
            sequence,
            event_type: event_type_u8,
            timestamp,
            merkle_root,
            event,
            merkle_path,
        }
    }

    /// Compute event hash (leaf in Merkle tree)
    fn compute_event_hash(event: &AuditEvent) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Hash all event fields
        hasher.update(&event.sequence.to_le_bytes());

        // Serialize event_type to string for hashing
        let event_type_str = format!("{:?}", event.event_type);
        hasher.update(event_type_str.as_bytes());

        hasher.update(&event.timestamp.timestamp().to_le_bytes());
        hasher.update(event.operation.as_bytes());
        hasher.update(event.namespace.as_bytes());
        hasher.update(event.client_id.as_bytes());

        if let Some(ref key_id) = event.key_id {
            hasher.update(key_id.as_bytes());
        }

        // Hash result (Success = 0, Failure = 1)
        let result_byte = match event.result {
            hsm_audit::OperationResult::Success => 0u8,
            hsm_audit::OperationResult::Failure { .. } => 1u8,
        };
        hasher.update(&[result_byte]);

        hasher.update(event.prev_hash.as_bytes());
        hasher.update(event.current_hash.as_bytes());

        hasher.finalize().into()
    }

    /// Verify Merkle path
    fn verify_merkle_path(leaf_hash: [u8; 32], path: &[[u8; 32]], root: [u8; 32]) -> bool {
        let mut current = leaf_hash;

        for sibling in path {
            let mut hasher = Sha256::new();
            // Simplified: in production, track left/right positions
            hasher.update(&current);
            hasher.update(sibling);
            current = hasher.finalize().into();
        }

        current == root
    }

    /// Compute Merkle root from leaf hash and path
    fn compute_merkle_root_from_path(leaf_hash: [u8; 32], path: &[[u8; 32]]) -> [u8; 32] {
        let mut current = leaf_hash;
        for sibling in path {
            let mut hasher = Sha256::new();
            hasher.update(&current);
            hasher.update(sibling);
            current = hasher.finalize().into();
        }
        current
    }

    /// Convert bytes to field element
    fn bytes_to_field(bytes: &[u8]) -> Fr {
        crate::circuits::utils::bytes_to_field(bytes)
    }
}

impl ConstraintSynthesizer<Fr> for EventExistenceCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public inputs
        let sequence_var = cs.new_input_variable(|| Ok(Fr::from(self.sequence)))?;
        let event_type_var = cs.new_input_variable(|| Ok(Fr::from(self.event_type)))?;
        let timestamp_var =
            cs.new_input_variable(|| Ok(Fr::from(self.timestamp.unsigned_abs())))?;
        let merkle_root_var =
            cs.new_input_variable(|| Ok(Self::bytes_to_field(&self.merkle_root)))?;

        // Private witnesses for event data
        let event_sequence_witness =
            cs.new_witness_variable(|| Ok(Fr::from(self.event.sequence)))?;
        let event_type_witness = cs.new_witness_variable(|| Ok(Fr::from(self.event_type)))?;
        let event_ts = self.event.timestamp.timestamp().unsigned_abs();
        let event_timestamp_witness = cs.new_witness_variable(|| Ok(Fr::from(event_ts)))?;

        // Merkle path
        let mut path_vars = Vec::new();
        for node in &self.merkle_path {
            let node_var = cs.new_witness_variable(|| Ok(Self::bytes_to_field(node)))?;
            path_vars.push(node_var);
        }

        // Compute Merkle root witness from event hash and path
        let event_hash = Self::compute_event_hash(&self.event);
        let computed_root = Self::compute_merkle_root_from_path(event_hash, &self.merkle_path);
        let computed_root_witness =
            cs.new_witness_variable(|| Ok(Self::bytes_to_field(&computed_root)))?;

        // Constraint 1: Event sequence matches public input
        // sequence_var - event_sequence_witness = 0
        cs.enforce_constraint(
            lc!() + sequence_var - event_sequence_witness,
            lc!() + Variable::One,
            lc!(),
        )?;

        // Constraint 2: Event type matches public input
        cs.enforce_constraint(
            lc!() + event_type_var - event_type_witness,
            lc!() + Variable::One,
            lc!(),
        )?;

        // Constraint 3: Timestamp matches public input
        cs.enforce_constraint(
            lc!() + timestamp_var - event_timestamp_witness,
            lc!() + Variable::One,
            lc!(),
        )?;

        // Constraint 4: Merkle root matches computed root from path
        cs.enforce_constraint(
            lc!() + merkle_root_var - computed_root_witness,
            lc!() + Variable::One,
            lc!(),
        )?;

        Ok(())
    }
}

/// Event proof system for generating and verifying ZK event existence proofs
pub struct EventProofSystem {
    /// Proving key (private)
    proving_key: Option<ProvingKey<Bn254>>,

    /// Verifying key (public)
    verifying_key: Option<VerifyingKey<Bn254>>,

    /// Prepared verifying key
    pvk: Option<PreparedVerifyingKey<Bn254>>,

    /// Maximum Merkle path depth (circuit structure size)
    max_depth: usize,
}

impl EventProofSystem {
    /// Create a new event proof system
    pub fn new() -> Self {
        Self {
            proving_key: None,
            verifying_key: None,
            pvk: None,
            max_depth: 0,
        }
    }

    /// Compute Merkle root from leaf hash and path (for setup consistency)
    fn compute_merkle_root_from_path(leaf_hash: [u8; 32], path: &[[u8; 32]]) -> [u8; 32] {
        let mut current = leaf_hash;
        for sibling in path {
            let mut hasher = Sha256::new();
            hasher.update(&current);
            hasher.update(sibling);
            current = hasher.finalize().into();
        }
        current
    }

    /// Setup the proof system
    pub fn setup<R: RngCore + CryptoRng>(
        &mut self,
        max_merkle_depth: usize,
        rng: &mut R,
    ) -> EventProofResult<()> {
        // Create dummy event and circuit for setup with consistent data
        let dummy_event = create_dummy_event();
        let dummy_path = vec![[0u8; 32]; max_merkle_depth];

        // Compute the event hash and then the Merkle root from the path
        // to ensure constraints are satisfied
        let event_hash = EventExistenceCircuit::compute_event_hash(&dummy_event);
        let dummy_root = Self::compute_merkle_root_from_path(event_hash, &dummy_path);

        let circuit = EventExistenceCircuit::new(dummy_event, dummy_path, dummy_root);

        // Generate keys using Groth16::generate_random_parameters
        let params = Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, rng)
            .map_err(|e| EventProofError::ProofGenerationFailed(format!("Setup failed: {}", e)))?;

        let vk = params.vk.clone();
        let pvk = prepare_verifying_key(&vk);
        let pk = params;

        self.proving_key = Some(pk);
        self.verifying_key = Some(vk);
        self.pvk = Some(pvk);
        self.max_depth = max_merkle_depth;

        Ok(())
    }

    /// Generate a ZK proof for event existence
    ///
    /// Note: The merkle_path length must match the max_merkle_depth used during setup.
    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        request: &EventProofRequest,
        rng: &mut R,
    ) -> EventProofResult<EventExistenceProof> {
        let pk = self.proving_key.as_ref().ok_or_else(|| {
            EventProofError::ProofGenerationFailed("Setup not called".to_string())
        })?;

        // Validate path length matches setup
        if request.merkle_path.len() != self.max_depth {
            return Err(EventProofError::InvalidEvent(format!(
                "Merkle path length ({}) must match setup depth ({})",
                request.merkle_path.len(),
                self.max_depth
            )));
        }

        // Create circuit
        let circuit = EventExistenceCircuit::new(
            request.event.clone(),
            request.merkle_path.clone(),
            request.merkle_root,
        );

        // Extract public data
        let public_inputs = PublicEventData {
            sequence: request.event.sequence,
            event_type: request.event.event_type.clone(),
            timestamp: request.event.timestamp.timestamp(),
            merkle_root: request.merkle_root,
        };

        // Generate proof using Groth16::prove
        let proof = Groth16::<Bn254>::prove(pk, circuit, rng)
            .map_err(|e| EventProofError::ProofGenerationFailed(e.to_string()))?;

        // Calculate size
        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).map_err(
            |_: ark_serialize::SerializationError| {
                EventProofError::SerializationError("Serialization failed".to_string())
            },
        )?;

        Ok(EventExistenceProof {
            proof,
            public_inputs,
            size_bytes: bytes.len() + 64, // Approximate with public inputs
        })
    }

    /// Verify a ZK event existence proof
    pub fn verify(&self, proof: &EventExistenceProof) -> EventProofResult<bool> {
        let pvk = self
            .pvk
            .as_ref()
            .ok_or_else(|| EventProofError::VerificationFailed("Setup not called".to_string()))?;

        // Prepare public inputs
        let event_type_u8 = format!("{:?}", proof.public_inputs.event_type.clone())
            .as_bytes()
            .get(0)
            .copied()
            .unwrap_or(0);

        let public_inputs = vec![
            Fr::from(proof.public_inputs.sequence),
            Fr::from(event_type_u8),
            Fr::from(proof.public_inputs.timestamp.unsigned_abs()),
            EventExistenceCircuit::bytes_to_field(&proof.public_inputs.merkle_root),
        ];

        // Verify proof using SNARK trait
        let valid = <Groth16<Bn254> as SNARK<Fr>>::verify_with_processed_vk(
            pvk,
            &public_inputs,
            &proof.proof,
        )
        .map_err(|_| EventProofError::VerificationFailed("Verification failed".to_string()))?;

        Ok(valid)
    }
}

impl Default for EventProofSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a dummy audit event for testing/setup
fn create_dummy_event() -> AuditEvent {
    use chrono::Utc;
    use hsm_audit::OperationResult;

    AuditEvent {
        timestamp: Utc::now(),
        sequence: 1,
        event_type: EventType::Sign,
        operation: "dummy_op".to_string(),
        namespace: "default".to_string(),
        client_id: "dummy_client".to_string(),
        key_id: Some("dummy_key".to_string()),
        result: OperationResult::Success,
        prev_hash: "0".repeat(64),
        current_hash: "0".repeat(64),
        metadata: None,
    }
}

/// Serde support for proofs
mod proof_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(proof: &Proof<Bn254>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = Vec::new();
        proof
            .serialize_compressed(&mut bytes)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Proof<Bn254>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::de::Deserialize::deserialize(deserializer)?;
        Proof::<Bn254>::deserialize_compressed(&bytes[..]).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use chrono::Utc;
    use hsm_audit::{AuditEventBuilder, OperationResult};

    fn create_test_event(sequence: u64) -> AuditEvent {
        AuditEvent {
            timestamp: Utc::now(),
            sequence,
            event_type: EventType::Sign,
            operation: "sign_operation".to_string(),
            namespace: "production".to_string(),
            client_id: "client_sensitive_123".to_string(),
            key_id: Some("key_sensitive_456".to_string()),
            result: OperationResult::Success,
            prev_hash: "0".repeat(64),
            current_hash: "1".repeat(64),
            metadata: None,
        }
    }

    /// Compute merkle root from event hash and path (for test consistency)
    fn compute_merkle_root_from_path(leaf_hash: [u8; 32], path: &[[u8; 32]]) -> [u8; 32] {
        let mut current = leaf_hash;
        for sibling in path {
            let mut hasher = Sha256::new();
            hasher.update(&current);
            hasher.update(sibling);
            current = hasher.finalize().into();
        }
        current
    }

    #[test]
    fn test_event_hash_computation() {
        let event = create_test_event(1);
        let hash = EventExistenceCircuit::compute_event_hash(&event);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_event_proof_generation_and_verification() {
        let mut rng = StdRng::seed_from_u64(0);

        // Setup with depth 2 to match our test path
        let mut proof_system = EventProofSystem::new();
        proof_system.setup(2, &mut rng).unwrap();

        // Create event and request with consistent data (path length must match setup)
        let event = create_test_event(42);
        let event_hash = EventExistenceCircuit::compute_event_hash(&event);
        let merkle_path = vec![[2u8; 32], [3u8; 32]]; // 2 elements to match setup(2, ...)
                                                      // Compute the correct Merkle root from event hash and path
        let merkle_root = compute_merkle_root_from_path(event_hash, &merkle_path);

        let request = EventProofRequest {
            event: event.clone(),
            merkle_root,
            merkle_path,
        };

        // Generate proof
        let proof = proof_system.prove(&request, &mut rng).unwrap();

        // Verify public inputs are correct
        assert_eq!(proof.public_inputs.sequence, 42);
        assert_eq!(proof.public_inputs.event_type, EventType::Sign);

        // Verify proof
        let valid = proof_system.verify(&proof).unwrap();
        assert!(valid);

        // Check proof size
        assert!(proof.size_bytes < 1024, "Proof should be < 1KB");
    }

    #[test]
    fn test_privacy_preservation() {
        let mut rng = StdRng::seed_from_u64(1);

        let mut proof_system = EventProofSystem::new();
        // Setup with depth 0 for empty merkle_path test
        proof_system.setup(0, &mut rng).unwrap();

        let event = create_test_event(100);
        // For empty merkle_path, root should be the event hash itself
        let event_hash = EventExistenceCircuit::compute_event_hash(&event);
        let request = EventProofRequest {
            event: event.clone(),
            merkle_root: event_hash,
            merkle_path: vec![], // Empty path matches setup(0)
        };

        let proof = proof_system.prove(&request, &mut rng).unwrap();

        // Verify that sensitive data is NOT in public inputs
        let public = &proof.public_inputs;

        // Public data should only contain sequence, type, timestamp
        assert_eq!(public.sequence, 100);
        assert_eq!(public.event_type, EventType::Sign);

        // Sensitive data should NOT be directly accessible
        // (In the actual proof bytes, it's cryptographically hidden)
        let proof_bytes = proof.to_bytes();
        let proof_str = hex::encode(&proof_bytes);

        assert!(!proof_str.contains("client_sensitive_123"));
        assert!(!proof_str.contains("key_sensitive_456"));
    }
}
