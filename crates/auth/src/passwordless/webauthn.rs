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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserVerification {
    /// User verification required
    Required,
    /// User verification preferred
    Preferred,
    /// User verification discouraged
    Discouraged,
}

impl Default for UserVerification {
    fn default() -> Self {
        Self::Preferred
    }
}

/// Resident key requirement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResidentKey {
    /// Resident key required (passkey)
    Required,
    /// Resident key preferred
    Preferred,
    /// Resident key discouraged
    Discouraged,
}

impl Default for ResidentKey {
    fn default() -> Self {
        Self::Discouraged
    }
}

/// Attestation conveyance preference
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationConveyance {
    /// No attestation
    None,
    /// Indirect attestation
    Indirect,
    /// Direct attestation
    Direct,
    /// Enterprise attestation
    Enterprise,
}

impl Default for AttestationConveyance {
    fn default() -> Self {
        Self::None
    }
}

/// COSE algorithm identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoseAlgorithm {
    /// ECDSA with P-256 and SHA-256
    #[serde(rename = "-7")]
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

impl Default for CoseAlgorithm {
    fn default() -> Self {
        Self::ES256
    }
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
    /// Origin (e.g., "https://example.com")
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

        // In a full implementation, we would:
        // 1. Parse the CBOR attestation object
        // 2. Extract and verify the authenticator data
        // 3. Verify the attestation statement
        // 4. Extract the public key

        // For now, we'll create a simplified credential
        // In production, use a proper WebAuthn library like webauthn-rs
        let credential = WebAuthnCredential {
            credential_id: credential_id.clone(),
            user_id: user_id.to_string(),
            public_key: attestation_object.clone(), // Should extract actual public key
            counter: 0,
            algorithm: CoseAlgorithm::ES256 as i32, // Should extract from attestation
            aaguid: None,
            user_handle: self.create_user_handle(user_id),
            name: credential_name,
            registered_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            last_used_at: None,
            backup_eligible: false,
            backed_up: false,
        };

        // Store credential
        let cred_id_base64 = credential.credential_id_base64();
        self.credentials
            .insert(cred_id_base64.clone(), credential.clone());

        // Update user index
        self.user_credentials
            .entry(user_id.to_string())
            .or_insert_with(Vec::new)
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

        let _signature = base64_url_decode(&response.response.signature)
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

        // In a full implementation, we would verify the signature here
        // using the stored public key

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
            hasher.update(&challenge_bytes);
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
        let before = self.pending_challenges.len();
        self.pending_challenges
            .retain(|_, challenge| !challenge.is_expired());
        before - self.pending_challenges.len()
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
}
