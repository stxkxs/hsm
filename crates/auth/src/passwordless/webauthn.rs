//! WebAuthn/FIDO2 Authentication
//!
//! Provides passwordless authentication via hardware security keys,
//! platform authenticators (Touch ID, Windows Hello), and passkeys.
//!
//! # Overview
//!
//! WebAuthn is a W3C standard for secure, passwordless authentication using
//! public key cryptography. It supports:
//!
//! - Hardware security keys (YubiKey, SoloKey, etc.)
//! - Platform authenticators (Touch ID, Face ID, Windows Hello)
//! - Roaming authenticators (cross-device passkeys)
//!
//! # Flow
//!
//! ```text
//! Registration:
//! 1. Server generates challenge
//! 2. Client creates credential via navigator.credentials.create()
//! 3. Server verifies attestation and stores credential
//!
//! Authentication:
//! 1. Server generates challenge
//! 2. Client signs challenge via navigator.credentials.get()
//! 3. Server verifies signature
//! ```

use crate::error::{AuthError, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

/// WebAuthn authenticator attachment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticatorAttachment {
    /// Platform authenticator (Touch ID, Windows Hello)
    Platform,
    /// Cross-platform authenticator (security key)
    #[serde(rename = "cross-platform")]
    CrossPlatform,
}

/// User verification requirement
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserVerification {
    /// User verification required
    Required,
    /// User verification preferred
    #[default]
    Preferred,
    /// User verification discouraged
    Discouraged,
}

/// Resident key requirement
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResidentKey {
    /// Resident key required (passkey)
    Required,
    /// Resident key preferred
    Preferred,
    /// Resident key discouraged
    #[default]
    Discouraged,
}

/// Attestation conveyance preference
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationConveyance {
    /// No attestation
    #[default]
    None,
    /// Indirect attestation
    Indirect,
    /// Direct attestation
    Direct,
    /// Enterprise attestation
    Enterprise,
}

/// COSE algorithm identifier
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoseAlgorithm {
    /// ECDSA with P-256 and SHA-256
    #[serde(rename = "-7")]
    #[default]
    ES256 = -7,
    /// ECDSA with P-384 and SHA-384
    #[serde(rename = "-35")]
    ES384 = -35,
    /// ECDSA with P-521 and SHA-512
    #[serde(rename = "-36")]
    ES512 = -36,
    /// RSA PKCS#1 with SHA-256
    #[serde(rename = "-257")]
    RS256 = -257,
    /// Ed25519
    #[serde(rename = "-8")]
    EdDSA = -8,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyCredParams {
    /// Credential type (always "public-key")
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Algorithm identifier
    pub alg: i32,
}

impl PubKeyCredParams {
    pub fn new(algorithm: CoseAlgorithm) -> Self {
        Self {
            cred_type: "public-key".to_string(),
            alg: algorithm as i32,
        }
    }
}

/// WebAuthn configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Relying party ID (usually domain name)
    pub rp_id: String,
    /// Relying party name
    pub rp_name: String,
    /// Origin (e.g., `https://example.com`)
    pub origin: String,
    /// Challenge timeout
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// User verification requirement
    #[serde(default)]
    pub user_verification: UserVerification,
    /// Resident key requirement
    #[serde(default)]
    pub resident_key: ResidentKey,
    /// Attestation preference
    #[serde(default)]
    pub attestation: AttestationConveyance,
    /// Supported algorithms
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<CoseAlgorithm>,
    /// Authenticator attachment preference
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
}

fn default_timeout() -> u64 {
    60000 // 60 seconds
}

fn default_algorithms() -> Vec<CoseAlgorithm> {
    vec![
        CoseAlgorithm::ES256,
        CoseAlgorithm::RS256,
        CoseAlgorithm::EdDSA,
    ]
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_name: "HSM".to_string(),
            origin: "https://localhost".to_string(),
            timeout_ms: 60000,
            user_verification: UserVerification::Preferred,
            resident_key: ResidentKey::Discouraged,
            attestation: AttestationConveyance::None,
            algorithms: default_algorithms(),
            authenticator_attachment: None,
        }
    }
}

impl WebAuthnConfig {
    /// Create config for a domain
    pub fn new(domain: &str, name: &str) -> Self {
        Self {
            rp_id: domain.to_string(),
            rp_name: name.to_string(),
            origin: format!("https://{}", domain),
            ..Default::default()
        }
    }

    /// Require platform authenticator (Touch ID, Windows Hello)
    pub fn platform_only(mut self) -> Self {
        self.authenticator_attachment = Some(AuthenticatorAttachment::Platform);
        self
    }

    /// Require cross-platform authenticator (security key)
    pub fn security_key_only(mut self) -> Self {
        self.authenticator_attachment = Some(AuthenticatorAttachment::CrossPlatform);
        self
    }

    /// Require passkey (resident key)
    pub fn passkey(mut self) -> Self {
        self.resident_key = ResidentKey::Required;
        self.user_verification = UserVerification::Required;
        self
    }

    /// Set user verification
    pub fn with_user_verification(mut self, uv: UserVerification) -> Self {
        self.user_verification = uv;
        self
    }
}

/// WebAuthn challenge
#[derive(Debug, Clone)]
pub struct WebAuthnChallenge {
    /// Challenge bytes
    pub challenge: Vec<u8>,
    /// User ID
    pub user_id: String,
    /// Challenge type
    pub challenge_type: ChallengeType,
    /// Creation time
    pub created_at: Instant,
    /// Expiration duration
    pub expires_in: Duration,
}

/// Challenge type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    /// Registration challenge
    Registration,
    /// Authentication challenge
    Authentication,
}

impl WebAuthnChallenge {
    /// Check if expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.expires_in
    }

    /// Get challenge as base64url
    pub fn challenge_base64(&self) -> String {
        base64_url_encode(&self.challenge)
    }
}

/// WebAuthn credential (stored after registration)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    /// Credential ID
    pub credential_id: Vec<u8>,
    /// User ID
    pub user_id: String,
    /// Public key (COSE format)
    pub public_key: Vec<u8>,
    /// Signature counter
    pub counter: u32,
    /// Algorithm used
    pub algorithm: i32,
    /// Authenticator AAGUID
    pub aaguid: Option<Vec<u8>>,
    /// User handle
    pub user_handle: Vec<u8>,
    /// Credential name/label
    pub name: Option<String>,
    /// Registration time
    pub registered_at: i64,
    /// Last used time
    pub last_used_at: Option<i64>,
    /// Backup eligibility
    pub backup_eligible: bool,
    /// Backup state
    pub backed_up: bool,
}

impl WebAuthnCredential {
    /// Get credential ID as base64url
    pub fn credential_id_base64(&self) -> String {
        base64_url_encode(&self.credential_id)
    }
}

/// Registration options (sent to client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnRegistration {
    /// Challenge (base64url)
    pub challenge: String,
    /// Relying party info
    pub rp: RelyingParty,
    /// User info
    pub user: WebAuthnUser,
    /// Supported algorithms
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PubKeyCredParams>,
    /// Timeout in milliseconds
    pub timeout: u64,
    /// Attestation preference
    pub attestation: String,
    /// Authenticator selection criteria
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: AuthenticatorSelection,
    /// Credentials to exclude (for re-registration prevention)
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Vec<CredentialDescriptor>,
}

/// Relying party info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelyingParty {
    /// Relying party ID
    pub id: String,
    /// Relying party name
    pub name: String,
}

/// WebAuthn user info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnUser {
    /// User ID (base64url)
    pub id: String,
    /// Username
    pub name: String,
    /// Display name
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelection {
    /// Authenticator attachment
    #[serde(
        rename = "authenticatorAttachment",
        skip_serializing_if = "Option::is_none"
    )]
    pub authenticator_attachment: Option<String>,
    /// Resident key requirement
    #[serde(rename = "residentKey")]
    pub resident_key: String,
    /// User verification
    #[serde(rename = "userVerification")]
    pub user_verification: String,
}

/// Credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDescriptor {
    /// Credential type
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Credential ID (base64url)
    pub id: String,
    /// Transports
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// Authentication verification options (sent to client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnVerification {
    /// Challenge (base64url)
    pub challenge: String,
    /// Relying party ID
    #[serde(rename = "rpId")]
    pub rp_id: String,
    /// Timeout in milliseconds
    pub timeout: u64,
    /// User verification
    #[serde(rename = "userVerification")]
    pub user_verification: String,
    /// Allowed credentials
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<CredentialDescriptor>,
}

/// Client registration response (from client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    /// Credential ID (base64url)
    pub id: String,
    /// Raw credential ID (base64url)
    #[serde(rename = "rawId")]
    pub raw_id: String,
    /// Response type
    #[serde(rename = "type")]
    pub response_type: String,
    /// Attestation response
    pub response: AttestationResponse,
    /// Client extension results
    #[serde(rename = "clientExtensionResults")]
    pub client_extension_results: serde_json::Value,
    /// Authenticator attachment
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
}

/// Attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResponse {
    /// Client data JSON (base64url)
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// Attestation object (base64url)
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    /// Transports
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// Client authentication response (from client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResponse {
    /// Credential ID (base64url)
    pub id: String,
    /// Raw credential ID (base64url)
    #[serde(rename = "rawId")]
    pub raw_id: String,
    /// Response type
    #[serde(rename = "type")]
    pub response_type: String,
    /// Assertion response
    pub response: AssertionResponse,
    /// Client extension results
    #[serde(rename = "clientExtensionResults")]
    pub client_extension_results: serde_json::Value,
    /// Authenticator attachment
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
}

/// Assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionResponse {
    /// Client data JSON (base64url)
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// Authenticator data (base64url)
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// Signature (base64url)
    pub signature: String,
    /// User handle (base64url, optional)
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

/// WebAuthn manager
pub struct WebAuthnManager {
    /// Configuration
    config: WebAuthnConfig,
    /// Pending challenges (challenge_hash -> WebAuthnChallenge)
    pending_challenges: DashMap<String, WebAuthnChallenge>,
    /// Stored credentials (credential_id_base64 -> WebAuthnCredential)
    credentials: DashMap<String, WebAuthnCredential>,
    /// User credentials index (user_id -> Vec<credential_id_base64>)
    user_credentials: DashMap<String, Vec<String>>,
}

impl WebAuthnManager {
    /// Create a new WebAuthn manager
    pub fn new(config: WebAuthnConfig) -> Self {
        Self {
            config,
            pending_challenges: DashMap::new(),
            credentials: DashMap::new(),
            user_credentials: DashMap::new(),
        }
    }

    /// Start registration for a user
    pub fn start_registration(
        &self,
        user_id: &str,
        username: &str,
        display_name: &str,
    ) -> Result<WebAuthnRegistration> {
        // Generate challenge
        let challenge = self.generate_challenge(user_id, ChallengeType::Registration)?;

        // Get user's existing credentials for exclusion
        let exclude_credentials = self.get_user_credential_descriptors(user_id);

        // Build user handle
        let user_handle = self.create_user_handle(user_id);

        let registration = WebAuthnRegistration {
            challenge: challenge.challenge_base64(),
            rp: RelyingParty {
                id: self.config.rp_id.clone(),
                name: self.config.rp_name.clone(),
            },
            user: WebAuthnUser {
                id: base64_url_encode(&user_handle),
                name: username.to_string(),
                display_name: display_name.to_string(),
            },
            pub_key_cred_params: self
                .config
                .algorithms
                .iter()
                .map(|alg| PubKeyCredParams::new(*alg))
                .collect(),
            timeout: self.config.timeout_ms,
            attestation: format!("{:?}", self.config.attestation).to_lowercase(),
            authenticator_selection: AuthenticatorSelection {
                authenticator_attachment: self
                    .config
                    .authenticator_attachment
                    .map(|a| format!("{:?}", a).to_lowercase()),
                resident_key: format!("{:?}", self.config.resident_key).to_lowercase(),
                user_verification: format!("{:?}", self.config.user_verification).to_lowercase(),
            },
            exclude_credentials,
        };

        Ok(registration)
    }

    /// Complete registration
    pub fn complete_registration(
        &self,
        user_id: &str,
        response: &RegistrationResponse,
        credential_name: Option<String>,
    ) -> Result<WebAuthnCredential> {
        // Validate challenge
        let _challenge = self.validate_challenge(user_id, ChallengeType::Registration)?;

        // Decode response
        let client_data = base64_url_decode(&response.response.client_data_json)
            .map_err(|_| AuthError::Internal("Invalid client data".to_string()))?;

        let attestation_object = base64_url_decode(&response.response.attestation_object)
            .map_err(|_| AuthError::Internal("Invalid attestation object".to_string()))?;

        // Parse client data
        let client_data_json: serde_json::Value = serde_json::from_slice(&client_data)
            .map_err(|_| AuthError::Internal("Invalid client data JSON".to_string()))?;

        // Verify type
        if client_data_json["type"].as_str() != Some("webauthn.create") {
            return Err(AuthError::Internal("Invalid client data type".to_string()));
        }

        // Verify origin
        if client_data_json["origin"].as_str() != Some(&self.config.origin) {
            return Err(AuthError::Internal("Origin mismatch".to_string()));
        }

        // Parse credential ID
        let credential_id = base64_url_decode(&response.raw_id)
            .map_err(|_| AuthError::Internal("Invalid credential ID".to_string()))?;

        // Parse the CBOR attestation object and extract the authenticator data.
        // We then parse the attested credential data to recover the COSE public
        // key that the authenticator generated. We store the *COSE key* (not the
        // raw attestation blob) so that we can verify assertion signatures during
        // authentication.
        let attestation = parse_attestation_object(&attestation_object)?;
        let auth_data = AuthenticatorData::parse(&attestation.auth_data)?;

        // Verify the RP ID hash binds this credential to our relying party.
        let expected_rp_hash = {
            let mut hasher = Sha256::new();
            hasher.update(self.config.rp_id.as_bytes());
            hasher.finalize()
        };
        if auth_data.rp_id_hash != expected_rp_hash.as_slice() {
            return Err(AuthError::Internal(
                "RP ID hash mismatch in attestation".to_string(),
            ));
        }

        let attested = auth_data.attested_credential.ok_or_else(|| {
            AuthError::Internal("Attestation missing attested credential data".to_string())
        })?;

        // The credential ID inside authData must match the one the client claims.
        if attested.credential_id != credential_id {
            return Err(AuthError::Internal(
                "Credential ID mismatch in attestation".to_string(),
            ));
        }

        // Parse the COSE public key so we can both validate it now and store it
        // in canonical form for later signature verification.
        let cose_key = CoseKey::parse(&attested.credential_public_key)?;

        let credential = WebAuthnCredential {
            credential_id: credential_id.clone(),
            user_id: user_id.to_string(),
            public_key: attested.credential_public_key.clone(),
            counter: auth_data.counter,
            algorithm: cose_key.algorithm(),
            aaguid: Some(attested.aaguid.clone()),
            user_handle: self.create_user_handle(user_id),
            name: credential_name,
            registered_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            last_used_at: None,
            backup_eligible: auth_data.backup_eligible,
            backed_up: auth_data.backed_up,
        };

        // Store credential
        let cred_id_base64 = credential.credential_id_base64();
        self.credentials
            .insert(cred_id_base64.clone(), credential.clone());

        // Update user index
        self.user_credentials
            .entry(user_id.to_string())
            .or_default()
            .push(cred_id_base64);

        Ok(credential)
    }

    /// Start authentication for a user
    pub fn start_authentication(&self, user_id: &str) -> Result<WebAuthnVerification> {
        // Check if user has credentials
        let allow_credentials = self.get_user_credential_descriptors(user_id);
        if allow_credentials.is_empty() {
            return Err(AuthError::InvalidSession(
                "No credentials registered".to_string(),
            ));
        }

        // Generate challenge
        let challenge = self.generate_challenge(user_id, ChallengeType::Authentication)?;

        Ok(WebAuthnVerification {
            challenge: challenge.challenge_base64(),
            rp_id: self.config.rp_id.clone(),
            timeout: self.config.timeout_ms,
            user_verification: format!("{:?}", self.config.user_verification).to_lowercase(),
            allow_credentials,
        })
    }

    /// Start authentication without specifying user (passkey flow)
    pub fn start_passkey_authentication(&self) -> Result<WebAuthnVerification> {
        // Generate challenge with empty user
        let challenge = self.generate_challenge("", ChallengeType::Authentication)?;

        Ok(WebAuthnVerification {
            challenge: challenge.challenge_base64(),
            rp_id: self.config.rp_id.clone(),
            timeout: self.config.timeout_ms,
            user_verification: format!("{:?}", self.config.user_verification).to_lowercase(),
            allow_credentials: vec![], // Empty for passkey (discoverable credentials)
        })
    }

    /// Complete authentication
    pub fn complete_authentication(&self, response: &AuthenticationResponse) -> Result<String> {
        // Decode credential ID
        let credential_id = base64_url_decode(&response.raw_id)
            .map_err(|_| AuthError::Internal("Invalid credential ID".to_string()))?;
        let cred_id_base64 = base64_url_encode(&credential_id);

        // Find credential
        let mut credential = self
            .credentials
            .get_mut(&cred_id_base64)
            .ok_or_else(|| AuthError::InvalidSession("Unknown credential".to_string()))?;

        // Validate challenge
        let _challenge =
            self.validate_challenge(&credential.user_id, ChallengeType::Authentication)?;

        // Decode response
        let client_data = base64_url_decode(&response.response.client_data_json)
            .map_err(|_| AuthError::Internal("Invalid client data".to_string()))?;

        let authenticator_data = base64_url_decode(&response.response.authenticator_data)
            .map_err(|_| AuthError::Internal("Invalid authenticator data".to_string()))?;

        let signature = base64_url_decode(&response.response.signature)
            .map_err(|_| AuthError::Internal("Invalid signature".to_string()))?;

        // Parse client data
        let client_data_json: serde_json::Value = serde_json::from_slice(&client_data)
            .map_err(|_| AuthError::Internal("Invalid client data JSON".to_string()))?;

        // Verify type
        if client_data_json["type"].as_str() != Some("webauthn.get") {
            return Err(AuthError::Internal("Invalid client data type".to_string()));
        }

        // Verify origin
        if client_data_json["origin"].as_str() != Some(&self.config.origin) {
            return Err(AuthError::Internal("Origin mismatch".to_string()));
        }

        // Verify RP ID hash (first 32 bytes of authenticator data)
        if authenticator_data.len() < 37 {
            return Err(AuthError::Internal(
                "Authenticator data too short".to_string(),
            ));
        }

        let rp_id_hash = &authenticator_data[0..32];
        let expected_rp_hash = {
            let mut hasher = Sha256::new();
            hasher.update(self.config.rp_id.as_bytes());
            hasher.finalize()
        };

        if rp_id_hash != expected_rp_hash.as_slice() {
            return Err(AuthError::Internal("RP ID hash mismatch".to_string()));
        }

        // Check flags
        let flags = authenticator_data[32];
        let user_present = flags & 0x01 != 0;
        let user_verified = flags & 0x04 != 0;

        if !user_present {
            return Err(AuthError::Internal("User not present".to_string()));
        }

        if self.config.user_verification == UserVerification::Required && !user_verified {
            return Err(AuthError::Internal(
                "User verification required".to_string(),
            ));
        }

        // Extract and verify counter
        let counter = u32::from_be_bytes([
            authenticator_data[33],
            authenticator_data[34],
            authenticator_data[35],
            authenticator_data[36],
        ]);

        // Counter should be greater than stored counter (replay protection)
        // Counter of 0 is special and doesn't need checking
        if counter != 0 && counter <= credential.counter {
            return Err(AuthError::Internal("Counter replay detected".to_string()));
        }

        // Verify the assertion signature. WebAuthn signs the concatenation of the
        // raw authenticator data and the SHA-256 of the clientDataJSON, using the
        // credential's private key. We verify with the stored COSE public key.
        //
        // This is the security-critical step: without it, any client that knows a
        // credential ID could authenticate as the owner. The signature MUST match.
        let client_data_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&client_data);
            hasher.finalize()
        };
        let mut signed_message = authenticator_data.clone();
        signed_message.extend_from_slice(&client_data_hash);

        let cose_key = CoseKey::parse(&credential.public_key)?;
        cose_key.verify_signature(&signed_message, &signature)?;

        // Update credential
        credential.counter = counter;
        credential.last_used_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        );

        Ok(credential.user_id.clone())
    }

    /// Generate a new challenge
    fn generate_challenge(
        &self,
        user_id: &str,
        challenge_type: ChallengeType,
    ) -> Result<WebAuthnChallenge> {
        let mut challenge_bytes = [0u8; 32];
        getrandom::getrandom(&mut challenge_bytes)
            .map_err(|_| AuthError::Internal("Failed to generate challenge".to_string()))?;

        let challenge = WebAuthnChallenge {
            challenge: challenge_bytes.to_vec(),
            user_id: user_id.to_string(),
            challenge_type,
            created_at: Instant::now(),
            expires_in: Duration::from_millis(self.config.timeout_ms),
        };

        // Store challenge
        let challenge_hash = {
            let mut hasher = Sha256::new();
            hasher.update(challenge_bytes);
            hex::encode(hasher.finalize())
        };
        self.pending_challenges
            .insert(challenge_hash, challenge.clone());

        Ok(challenge)
    }

    /// Validate and consume a challenge
    fn validate_challenge(
        &self,
        user_id: &str,
        expected_type: ChallengeType,
    ) -> Result<WebAuthnChallenge> {
        // Find the challenge for this user
        let mut found_key = None;
        for entry in self.pending_challenges.iter() {
            let challenge = entry.value();
            if challenge.user_id == user_id && challenge.challenge_type == expected_type {
                found_key = Some(entry.key().clone());
                break;
            }
        }

        let key = found_key
            .ok_or_else(|| AuthError::InvalidSession("No pending challenge".to_string()))?;

        let (_, challenge) = self
            .pending_challenges
            .remove(&key)
            .ok_or_else(|| AuthError::InvalidSession("Challenge already used".to_string()))?;

        if challenge.is_expired() {
            return Err(AuthError::SessionExpired);
        }

        Ok(challenge)
    }

    /// Get credential descriptors for a user
    fn get_user_credential_descriptors(&self, user_id: &str) -> Vec<CredentialDescriptor> {
        self.user_credentials
            .get(user_id)
            .map(|creds| {
                creds
                    .iter()
                    .filter_map(|cred_id| {
                        self.credentials
                            .get(cred_id)
                            .map(|cred| CredentialDescriptor {
                                cred_type: "public-key".to_string(),
                                id: cred.credential_id_base64(),
                                transports: Some(vec![
                                    "usb".to_string(),
                                    "nfc".to_string(),
                                    "ble".to_string(),
                                    "internal".to_string(),
                                ]),
                            })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Create user handle from user ID
    fn create_user_handle(&self, user_id: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(user_id.as_bytes());
        hasher.update(self.config.rp_id.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Get user's credentials
    pub fn get_user_credentials(&self, user_id: &str) -> Vec<WebAuthnCredential> {
        self.user_credentials
            .get(user_id)
            .map(|cred_ids| {
                cred_ids
                    .iter()
                    .filter_map(|id| self.credentials.get(id).map(|c| c.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Remove a credential
    pub fn remove_credential(&self, user_id: &str, credential_id: &str) -> bool {
        // Remove from credentials
        if self.credentials.remove(credential_id).is_some() {
            // Remove from user index
            if let Some(mut creds) = self.user_credentials.get_mut(user_id) {
                creds.retain(|id| id != credential_id);
            }
            true
        } else {
            false
        }
    }

    /// Cleanup expired challenges
    pub fn cleanup_expired_challenges(&self) -> usize {
        // Count removals inside `retain` rather than diffing two `len()`
        // snapshots: concurrent inserts between the snapshots can make the
        // second length larger, underflowing the `usize` subtraction.
        let mut removed = 0usize;
        self.pending_challenges.retain(|_, challenge| {
            let keep = !challenge.is_expired();
            if !keep {
                removed += 1;
            }
            keep
        });
        removed
    }

    /// Check if user has any credentials
    pub fn user_has_credentials(&self, user_id: &str) -> bool {
        self.user_credentials
            .get(user_id)
            .map(|c| !c.is_empty())
            .unwrap_or(false)
    }
}

impl Default for WebAuthnManager {
    fn default() -> Self {
        Self::new(WebAuthnConfig::default())
    }
}

// ---------------------------------------------------------------------------
// Attestation object / authenticator data / COSE key parsing
// ---------------------------------------------------------------------------

/// Parsed attestation object (CBOR map produced by the authenticator).
struct AttestationObject {
    auth_data: Vec<u8>,
}

/// Parse the CBOR attestation object and extract the raw `authData` bytes.
fn parse_attestation_object(bytes: &[u8]) -> Result<AttestationObject> {
    let value: ciborium::value::Value = ciborium::from_reader(bytes)
        .map_err(|_| AuthError::Internal("Invalid CBOR attestation object".to_string()))?;

    let map = value
        .as_map()
        .ok_or_else(|| AuthError::Internal("Attestation object is not a map".to_string()))?;

    let mut auth_data = None;
    for (k, v) in map {
        if k.as_text() == Some("authData") {
            auth_data = v.as_bytes().cloned();
        }
    }

    let auth_data = auth_data
        .ok_or_else(|| AuthError::Internal("Attestation object missing authData".to_string()))?;

    Ok(AttestationObject { auth_data })
}

/// Attested credential data embedded in `authData`.
struct AttestedCredentialData {
    aaguid: Vec<u8>,
    credential_id: Vec<u8>,
    credential_public_key: Vec<u8>,
}

/// Parsed authenticator data.
struct AuthenticatorData {
    rp_id_hash: Vec<u8>,
    counter: u32,
    backup_eligible: bool,
    backed_up: bool,
    attested_credential: Option<AttestedCredentialData>,
}

impl AuthenticatorData {
    /// Parse authenticator data per the WebAuthn spec layout:
    /// rpIdHash(32) || flags(1) || signCount(4) || [attestedCredentialData] || [extensions]
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 37 {
            return Err(AuthError::Internal(
                "Authenticator data too short".to_string(),
            ));
        }

        let rp_id_hash = bytes[0..32].to_vec();
        let flags = bytes[32];
        let counter = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);

        let attested_present = flags & 0x40 != 0; // AT flag (bit 6)
        let backup_eligible = flags & 0x08 != 0; // BE flag (bit 3)
        let backed_up = flags & 0x10 != 0; // BS flag (bit 4)

        let attested_credential = if attested_present {
            // attestedCredentialData: aaguid(16) || credIdLen(2 BE) || credId(L) || COSE key (CBOR)
            if bytes.len() < 37 + 18 {
                return Err(AuthError::Internal(
                    "Attested credential data too short".to_string(),
                ));
            }
            let aaguid = bytes[37..53].to_vec();
            let cred_id_len = u16::from_be_bytes([bytes[53], bytes[54]]) as usize;
            let cred_id_start: usize = 55;
            let cred_id_end = cred_id_start
                .checked_add(cred_id_len)
                .ok_or_else(|| AuthError::Internal("Credential ID length overflow".to_string()))?;
            if bytes.len() < cred_id_end {
                return Err(AuthError::Internal(
                    "Credential ID exceeds authenticator data".to_string(),
                ));
            }
            let credential_id = bytes[cred_id_start..cred_id_end].to_vec();

            // The remaining bytes start the COSE_Key (and possibly extensions).
            // Read exactly one CBOR item so trailing extension data is ignored.
            let key_slice = &bytes[cred_id_end..];
            let mut reader = key_slice;
            let key_value: ciborium::value::Value = ciborium::from_reader(&mut reader)
                .map_err(|_| AuthError::Internal("Invalid COSE key CBOR".to_string()))?;
            // Re-encode the single parsed COSE_Key item into canonical bytes so
            // we store only the public key (without any trailing extensions).
            let mut canonical = Vec::new();
            ciborium::into_writer(&key_value, &mut canonical)
                .map_err(|_| AuthError::Internal("Failed to encode COSE key".to_string()))?;

            Some(AttestedCredentialData {
                aaguid,
                credential_id,
                credential_public_key: canonical,
            })
        } else {
            None
        };

        Ok(AuthenticatorData {
            rp_id_hash,
            counter,
            backup_eligible,
            backed_up,
            attested_credential,
        })
    }
}

/// Parsed COSE public key (subset: EC2 / RSA).
enum CoseKey {
    /// EC2 key: curve + uncompressed point coordinates.
    Ec2 { alg: i64, x: Vec<u8>, y: Vec<u8> },
    /// RSA key: modulus (n) and exponent (e).
    Rsa { alg: i64, n: Vec<u8>, e: Vec<u8> },
}

impl CoseKey {
    /// Parse a COSE_Key CBOR map. We support EC2 (kty=2) and RSA (kty=3).
    fn parse(bytes: &[u8]) -> Result<Self> {
        let value: ciborium::value::Value = ciborium::from_reader(bytes)
            .map_err(|_| AuthError::Internal("Invalid COSE key CBOR".to_string()))?;
        let map = value
            .as_map()
            .ok_or_else(|| AuthError::Internal("COSE key is not a map".to_string()))?;

        // COSE label -> value lookup (labels are integers).
        let get = |label: i64| -> Option<&ciborium::value::Value> {
            map.iter()
                .find(|(k, _)| {
                    k.as_integer().and_then(|i| i128::from(i).try_into().ok()) == Some(label)
                })
                .map(|(_, v)| v)
        };

        let as_int = |v: &ciborium::value::Value| -> Option<i64> {
            v.as_integer().and_then(|i| i128::from(i).try_into().ok())
        };

        let kty = get(1)
            .and_then(as_int)
            .ok_or_else(|| AuthError::Internal("COSE key missing kty".to_string()))?;
        let alg = get(3)
            .and_then(as_int)
            .ok_or_else(|| AuthError::Internal("COSE key missing alg".to_string()))?;

        match kty {
            2 => {
                // EC2
                let x = get(-2)
                    .and_then(|v| v.as_bytes().cloned())
                    .ok_or_else(|| AuthError::Internal("COSE EC2 key missing x".to_string()))?;
                let y = get(-3)
                    .and_then(|v| v.as_bytes().cloned())
                    .ok_or_else(|| AuthError::Internal("COSE EC2 key missing y".to_string()))?;
                Ok(CoseKey::Ec2 { alg, x, y })
            }
            3 => {
                // RSA
                let n = get(-1)
                    .and_then(|v| v.as_bytes().cloned())
                    .ok_or_else(|| AuthError::Internal("COSE RSA key missing n".to_string()))?;
                let e = get(-2)
                    .and_then(|v| v.as_bytes().cloned())
                    .ok_or_else(|| AuthError::Internal("COSE RSA key missing e".to_string()))?;
                Ok(CoseKey::Rsa { alg, n, e })
            }
            _ => Err(AuthError::Internal(format!(
                "Unsupported COSE key type: {}",
                kty
            ))),
        }
    }

    /// The COSE algorithm identifier of this key.
    fn algorithm(&self) -> i32 {
        match self {
            CoseKey::Ec2 { alg, .. } | CoseKey::Rsa { alg, .. } => *alg as i32,
        }
    }

    /// Verify a signature over `message` using this COSE public key.
    ///
    /// WebAuthn ECDSA signatures are ASN.1 DER encoded (not the raw R||S used by
    /// JWT). RSA signatures are PKCS#1 v1.5.
    fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            CoseKey::Ec2 { alg, x, y } => match alg {
                // ES256 (-7): P-256 + SHA-256
                -7 => {
                    use p256::ecdsa::{signature::Verifier, DerSignature, VerifyingKey};
                    use p256::EncodedPoint;

                    if x.len() != 32 || y.len() != 32 {
                        return Err(AuthError::Internal(
                            "Invalid P-256 coordinate length".to_string(),
                        ));
                    }
                    let point = EncodedPoint::from_affine_coordinates(
                        p256::FieldBytes::from_slice(x),
                        p256::FieldBytes::from_slice(y),
                        false,
                    );
                    let key = VerifyingKey::from_encoded_point(&point)
                        .map_err(|_| AuthError::Internal("Invalid P-256 public key".to_string()))?;
                    let sig = DerSignature::try_from(signature).map_err(|_| {
                        AuthError::Internal("Invalid ECDSA DER signature".to_string())
                    })?;
                    key.verify(message, &sig).map_err(|_| {
                        AuthError::Unauthorized(
                            "WebAuthn signature verification failed".to_string(),
                        )
                    })
                }
                // ES384 (-35): P-384 + SHA-384
                -35 => {
                    use p384::ecdsa::{signature::Verifier, DerSignature, VerifyingKey};
                    use p384::EncodedPoint;

                    if x.len() != 48 || y.len() != 48 {
                        return Err(AuthError::Internal(
                            "Invalid P-384 coordinate length".to_string(),
                        ));
                    }
                    let point = EncodedPoint::from_affine_coordinates(
                        p384::FieldBytes::from_slice(x),
                        p384::FieldBytes::from_slice(y),
                        false,
                    );
                    let key = VerifyingKey::from_encoded_point(&point)
                        .map_err(|_| AuthError::Internal("Invalid P-384 public key".to_string()))?;
                    let sig = DerSignature::try_from(signature).map_err(|_| {
                        AuthError::Internal("Invalid ECDSA DER signature".to_string())
                    })?;
                    key.verify(message, &sig).map_err(|_| {
                        AuthError::Unauthorized(
                            "WebAuthn signature verification failed".to_string(),
                        )
                    })
                }
                other => Err(AuthError::Internal(format!(
                    "Unsupported COSE EC algorithm: {}",
                    other
                ))),
            },
            CoseKey::Rsa { alg, n, e } => match alg {
                // RS256 (-257): RSASSA-PKCS1-v1_5 + SHA-256
                -257 => {
                    use rsa::pkcs1v15::{
                        Signature as RsaSignature, VerifyingKey as RsaVerifyingKey,
                    };
                    use rsa::signature::Verifier;
                    use rsa::BigUint;

                    let modulus = BigUint::from_bytes_be(n);
                    let exponent = BigUint::from_bytes_be(e);
                    let public_key = rsa::RsaPublicKey::new(modulus, exponent)
                        .map_err(|_| AuthError::Internal("Invalid RSA public key".to_string()))?;
                    let verifying_key = RsaVerifyingKey::<Sha256>::new(public_key);
                    let sig = RsaSignature::try_from(signature)
                        .map_err(|_| AuthError::Internal("Invalid RSA signature".to_string()))?;
                    verifying_key.verify(message, &sig).map_err(|_| {
                        AuthError::Unauthorized(
                            "WebAuthn signature verification failed".to_string(),
                        )
                    })
                }
                other => Err(AuthError::Internal(format!(
                    "Unsupported COSE RSA algorithm: {}",
                    other
                ))),
            },
        }
    }
}

// Helper functions

fn base64_url_encode(data: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(data: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.decode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webauthn_config() {
        let config = WebAuthnConfig::new("example.com", "Example App")
            .passkey()
            .with_user_verification(UserVerification::Required);

        assert_eq!(config.rp_id, "example.com");
        assert_eq!(config.resident_key, ResidentKey::Required);
        assert_eq!(config.user_verification, UserVerification::Required);
    }

    #[test]
    fn test_start_registration() {
        let config = WebAuthnConfig::new("example.com", "Example App");
        let manager = WebAuthnManager::new(config);

        let registration = manager
            .start_registration("user-123", "testuser", "Test User")
            .unwrap();

        assert!(!registration.challenge.is_empty());
        assert_eq!(registration.rp.id, "example.com");
        assert_eq!(registration.user.name, "testuser");
    }

    #[test]
    fn test_start_authentication_no_credentials() {
        let config = WebAuthnConfig::new("example.com", "Example App");
        let manager = WebAuthnManager::new(config);

        let result = manager.start_authentication("user-123");
        assert!(result.is_err());
    }

    #[test]
    fn test_credential_descriptor() {
        let desc = CredentialDescriptor {
            cred_type: "public-key".to_string(),
            id: "test-id".to_string(),
            transports: Some(vec!["usb".to_string()]),
        };

        let json = serde_json::to_string(&desc).unwrap();
        assert!(json.contains("public-key"));
    }

    #[test]
    fn test_challenge_expiration() {
        let challenge = WebAuthnChallenge {
            challenge: vec![1, 2, 3],
            user_id: "user-123".to_string(),
            challenge_type: ChallengeType::Registration,
            created_at: Instant::now() - Duration::from_secs(120),
            expires_in: Duration::from_secs(60),
        };

        assert!(challenge.is_expired());
    }

    // ----- Signature verification tests (#3) -----

    use ciborium::value::Value as CborValue;
    use p256::ecdsa::SigningKey;

    /// Build a COSE_Key (EC2/ES256) CBOR map for a P-256 public key.
    fn cose_key_es256(vk: &p256::ecdsa::VerifyingKey) -> Vec<u8> {
        let point = vk.to_encoded_point(false);
        let x = point.x().unwrap().to_vec();
        let y = point.y().unwrap().to_vec();

        // COSE_Key map: 1(kty)=2(EC2), 3(alg)=-7(ES256), -1(crv)=1(P-256), -2(x), -3(y)
        let map = CborValue::Map(vec![
            (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
            (
                CborValue::Integer(3.into()),
                CborValue::Integer((-7).into()),
            ),
            (
                CborValue::Integer((-1).into()),
                CborValue::Integer(1.into()),
            ),
            (CborValue::Integer((-2).into()), CborValue::Bytes(x)),
            (CborValue::Integer((-3).into()), CborValue::Bytes(y)),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&map, &mut out).unwrap();
        out
    }

    /// Build authData embedding the supplied COSE key (registration form).
    fn build_auth_data(
        rp_id: &str,
        credential_id: &[u8],
        cose_key: &[u8],
        counter: u32,
    ) -> Vec<u8> {
        let mut auth_data = Vec::new();
        let rp_hash = {
            let mut h = Sha256::new();
            h.update(rp_id.as_bytes());
            h.finalize()
        };
        auth_data.extend_from_slice(&rp_hash);
        // flags: UP(0x01) | UV(0x04) | AT(0x40)
        auth_data.push(0x01 | 0x04 | 0x40);
        auth_data.extend_from_slice(&counter.to_be_bytes());
        // attestedCredentialData: aaguid(16) || credIdLen(2) || credId || COSE key
        auth_data.extend_from_slice(&[0u8; 16]);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(cose_key);
        auth_data
    }

    /// Build a CBOR attestation object wrapping authData ("none" fmt).
    fn build_attestation_object(auth_data: &[u8]) -> Vec<u8> {
        let map = CborValue::Map(vec![
            (
                CborValue::Text("fmt".to_string()),
                CborValue::Text("none".to_string()),
            ),
            (
                CborValue::Text("attStmt".to_string()),
                CborValue::Map(vec![]),
            ),
            (
                CborValue::Text("authData".to_string()),
                CborValue::Bytes(auth_data.to_vec()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&map, &mut out).unwrap();
        out
    }

    fn client_data_json(typ: &str, challenge_b64: &str, origin: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"{}","challenge":"{}","origin":"{}"}}"#,
            typ, challenge_b64, origin
        )
        .into_bytes()
    }

    /// Register a credential using a real P-256 key; returns (signing_key, credential_id).
    fn register_es256(manager: &WebAuthnManager, user_id: &str) -> (SigningKey, Vec<u8>) {
        let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
        let verifying_key = *signing_key.verifying_key();
        let credential_id = vec![9u8; 16];
        let cose_key = cose_key_es256(&verifying_key);

        let reg = manager.start_registration(user_id, "user", "User").unwrap();

        let auth_data = build_auth_data(&manager.config.rp_id, &credential_id, &cose_key, 0);
        let attestation_object = build_attestation_object(&auth_data);
        let cdj = client_data_json("webauthn.create", &reg.challenge, &manager.config.origin);

        let response = RegistrationResponse {
            id: base64_url_encode(&credential_id),
            raw_id: base64_url_encode(&credential_id),
            response_type: "public-key".to_string(),
            response: AttestationResponse {
                client_data_json: base64_url_encode(&cdj),
                attestation_object: base64_url_encode(&attestation_object),
                transports: None,
            },
            client_extension_results: serde_json::json!({}),
            authenticator_attachment: None,
        };

        let cred = manager
            .complete_registration(user_id, &response, Some("test".to_string()))
            .unwrap();
        assert_eq!(cred.algorithm, -7);
        assert_eq!(cred.credential_id, credential_id);
        // The stored public key must be the COSE key, not the raw attestation blob.
        assert!(CoseKey::parse(&cred.public_key).is_ok());

        (signing_key, credential_id)
    }

    fn make_assertion(
        manager: &WebAuthnManager,
        signing_key: &SigningKey,
        credential_id: &[u8],
        challenge_b64: &str,
        counter: u32,
        tamper: bool,
    ) -> AuthenticationResponse {
        use p256::ecdsa::{signature::Signer, DerSignature};

        // authData for assertion: no attested credential (AT flag clear).
        let mut auth_data = Vec::new();
        let rp_hash = {
            let mut h = Sha256::new();
            h.update(manager.config.rp_id.as_bytes());
            h.finalize()
        };
        auth_data.extend_from_slice(&rp_hash);
        auth_data.push(0x01 | 0x04); // UP | UV
        auth_data.extend_from_slice(&counter.to_be_bytes());

        let cdj = client_data_json("webauthn.get", challenge_b64, &manager.config.origin);
        let client_data_hash = {
            let mut h = Sha256::new();
            h.update(&cdj);
            h.finalize()
        };

        let mut signed = auth_data.clone();
        signed.extend_from_slice(&client_data_hash);

        let sig_bytes = if tamper {
            // A structurally valid DER signature that does NOT match the message.
            let der_sig2: DerSignature = signing_key.sign(b"a totally different message");
            der_sig2.as_bytes().to_vec()
        } else {
            let der_sig: DerSignature = signing_key.sign(&signed);
            der_sig.as_bytes().to_vec()
        };

        AuthenticationResponse {
            id: base64_url_encode(credential_id),
            raw_id: base64_url_encode(credential_id),
            response_type: "public-key".to_string(),
            response: AssertionResponse {
                client_data_json: base64_url_encode(&cdj),
                authenticator_data: base64_url_encode(&auth_data),
                signature: base64_url_encode(&sig_bytes),
                user_handle: None,
            },
            client_extension_results: serde_json::json!({}),
            authenticator_attachment: None,
        }
    }

    #[test]
    fn test_registration_extracts_cose_public_key() {
        let manager = WebAuthnManager::new(WebAuthnConfig::new("example.com", "Example"));
        let (_sk, _cid) = register_es256(&manager, "user-1");
    }

    #[test]
    fn test_valid_assertion_accepted() {
        let manager = WebAuthnManager::new(WebAuthnConfig::new("example.com", "Example"));
        let (signing_key, credential_id) = register_es256(&manager, "user-1");

        let verification = manager.start_authentication("user-1").unwrap();
        let assertion = make_assertion(
            &manager,
            &signing_key,
            &credential_id,
            &verification.challenge,
            5,
            false,
        );

        let user = manager.complete_authentication(&assertion).unwrap();
        assert_eq!(user, "user-1");
    }

    #[test]
    fn test_forged_assertion_signature_rejected() {
        let manager = WebAuthnManager::new(WebAuthnConfig::new("example.com", "Example"));
        let (signing_key, credential_id) = register_es256(&manager, "user-1");

        let verification = manager.start_authentication("user-1").unwrap();
        // tamper=true -> structurally valid DER signature that does not match.
        let assertion = make_assertion(
            &manager,
            &signing_key,
            &credential_id,
            &verification.challenge,
            5,
            true,
        );

        let result = manager.complete_authentication(&assertion);
        assert!(
            result.is_err(),
            "forged/mismatched assertion signature must be rejected"
        );
    }

    #[test]
    fn test_assertion_with_wrong_key_rejected() {
        let manager = WebAuthnManager::new(WebAuthnConfig::new("example.com", "Example"));
        let (_signing_key, credential_id) = register_es256(&manager, "user-1");

        // An attacker who knows the credential ID signs with their OWN key.
        let attacker_key = SigningKey::random(&mut rand::rngs::OsRng);
        let verification = manager.start_authentication("user-1").unwrap();
        let assertion = make_assertion(
            &manager,
            &attacker_key,
            &credential_id,
            &verification.challenge,
            5,
            false,
        );

        let result = manager.complete_authentication(&assertion);
        assert!(
            result.is_err(),
            "assertion signed by a non-owner key must be rejected"
        );
    }

    #[test]
    fn test_cleanup_expired_challenges_no_underflow() {
        let manager = WebAuthnManager::new(WebAuthnConfig::default());
        let expired = WebAuthnChallenge {
            challenge: vec![1, 2, 3],
            user_id: "u".to_string(),
            challenge_type: ChallengeType::Authentication,
            created_at: Instant::now() - Duration::from_secs(3600),
            expires_in: Duration::from_secs(1),
        };
        manager
            .pending_challenges
            .insert("k1".to_string(), expired.clone());
        let fresh = WebAuthnChallenge {
            created_at: Instant::now(),
            expires_in: Duration::from_secs(3600),
            ..expired
        };
        manager.pending_challenges.insert("k2".to_string(), fresh);

        let removed = manager.cleanup_expired_challenges();
        assert_eq!(removed, 1);
        // A second cleanup removes nothing and must not underflow.
        assert_eq!(manager.cleanup_expired_challenges(), 0);
    }
}
