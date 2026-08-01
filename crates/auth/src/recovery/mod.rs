//! Account Recovery
//!
//! Provides multiple account recovery methods for when users lose access to their credentials:
//! - Email recovery
//! - SMS recovery (with phone verification)
//! - Backup codes
//! - Social recovery (trusted guardians)
//! - Time-locked recovery
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     Account Recovery Flow                        │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                   │
//! │  1. Initiate Recovery                                             │
//! │     ┌──────────────┐                                             │
//! │     │  User Lost   │                                             │
//! │     │  Access      │                                             │
//! │     └──────┬───────┘                                             │
//! │            │                                                      │
//! │            ▼                                                      │
//! │     ┌──────────────┐     ┌──────────────────────────────┐       │
//! │     │  Select      │────▶│  Available Recovery Methods  │       │
//! │     │  Method      │     │  • Email                     │       │
//! │     └──────────────┘     │  • SMS                       │       │
//! │                          │  • Backup Codes              │       │
//! │                          │  • Social Recovery           │       │
//! │                          │  • Time-Locked               │       │
//! │                          └──────────────────────────────┘       │
//! │                                                                   │
//! │  2. Verify Identity                                               │
//! │     ┌──────────────┐     ┌──────────────┐                        │
//! │     │  Submit      │────▶│  Verify      │                        │
//! │     │  Proof       │     │  Proof       │                        │
//! │     └──────────────┘     └──────┬───────┘                        │
//! │                                 │                                 │
//! │                                 ▼                                 │
//! │  3. Reset Credentials                                             │
//! │     ┌──────────────────────────────────────────┐                 │
//! │     │  • Reset MFA                              │                 │
//! │     │  • Generate New Recovery Codes            │                 │
//! │     │  • Revoke Old Sessions                    │                 │
//! │     └──────────────────────────────────────────┘                 │
//! │                                                                   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use crate::error::{AuthError, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Recovery method types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RecoveryMethod {
    /// Email-based recovery
    Email { email: String },
    /// SMS-based recovery
    Sms {
        phone: String,
        /// Last 4 digits shown to user for verification
        phone_hint: String,
    },
    /// Backup codes
    BackupCodes {
        /// Number of remaining codes
        remaining_count: usize,
    },
    /// Social recovery via trusted guardians
    SocialRecovery {
        /// Required number of guardian approvals
        threshold: usize,
        /// Total number of guardians
        total_guardians: usize,
    },
    /// Time-locked recovery
    TimeLocked {
        /// Delay before recovery completes
        delay_hours: u32,
    },
}

/// Recovery request status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    /// Request initiated, awaiting verification
    Pending,
    /// Verification in progress
    Verifying,
    /// Waiting for time lock
    TimeLocked,
    /// Waiting for guardian approvals
    AwaitingGuardians,
    /// Request approved, can reset credentials
    Approved,
    /// Request completed
    Completed,
    /// Request expired
    Expired,
    /// Request denied/cancelled
    Denied,
}

/// Guardian status for social recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianApproval {
    /// Guardian identifier
    pub guardian_id: String,
    /// Guardian display name
    pub guardian_name: String,
    /// Whether approved
    pub approved: bool,
    /// Approval timestamp
    pub approved_at: Option<i64>,
    /// Approval IP address
    pub approved_from_ip: Option<String>,
}

/// Recovery verification proof
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VerificationProof {
    /// Code from email/SMS
    Code { code: String },
    /// Backup code
    BackupCode { code: String },
    /// Guardian approval token
    GuardianToken { guardian_id: String, token: String },
}

/// Recovery request
#[derive(Debug, Clone)]
pub struct RecoveryRequest {
    /// Request ID
    pub id: String,
    /// User ID
    pub user_id: String,
    /// Selected recovery method
    pub method: RecoveryMethod,
    /// Current status
    pub status: RecoveryStatus,
    /// Creation time
    pub created_at: Instant,
    /// System creation timestamp
    pub created_timestamp: i64,
    /// Expiration duration
    pub expires_in: Duration,
    /// Verification code hash (for email/SMS)
    pub verification_hash: Option<String>,
    /// Guardian approvals (for social recovery)
    pub guardian_approvals: Vec<GuardianApproval>,
    /// Time lock end (for time-locked recovery)
    pub time_lock_ends_at: Option<i64>,
    /// Request IP address
    pub request_ip: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Number of verification attempts
    pub attempts: u32,
    /// Maximum attempts allowed
    pub max_attempts: u32,
}

impl RecoveryRequest {
    /// Check if request is expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.expires_in
    }

    /// Check if time lock has passed
    pub fn time_lock_passed(&self) -> bool {
        if let Some(ends_at) = self.time_lock_ends_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            now >= ends_at
        } else {
            true
        }
    }

    /// Check if enough guardians have approved
    pub fn has_guardian_quorum(&self, threshold: usize) -> bool {
        self.guardian_approvals
            .iter()
            .filter(|g| g.approved)
            .count()
            >= threshold
    }
}

/// Recovery configuration
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    /// Request expiration time
    pub request_ttl: Duration,
    /// Verification code expiration
    pub code_ttl: Duration,
    /// Maximum verification attempts
    pub max_attempts: u32,
    /// Time lock delay (hours)
    pub time_lock_hours: u32,
    /// Verification code length
    pub code_length: usize,
    /// Minimum guardians for social recovery
    pub min_guardians: usize,
    /// Guardian threshold (ratio of required approvals)
    pub guardian_threshold_ratio: f32,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            request_ttl: Duration::from_secs(24 * 3600), // 24 hours
            code_ttl: Duration::from_secs(600),          // 10 minutes
            max_attempts: 5,
            time_lock_hours: 24,
            code_length: 6,
            min_guardians: 3,
            guardian_threshold_ratio: 0.5, // Majority
        }
    }
}

/// User recovery configuration (stored per user)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecoveryConfig {
    /// User ID
    pub user_id: String,
    /// Recovery email
    pub email: Option<String>,
    /// Recovery phone (E.164 format)
    pub phone: Option<String>,
    /// Backup code hashes
    pub backup_code_hashes: Vec<String>,
    /// Guardians for social recovery
    pub guardians: Vec<Guardian>,
    /// Time-locked recovery enabled
    pub time_locked_enabled: bool,
    /// Time lock delay (hours)
    pub time_lock_hours: u32,
    /// Last updated timestamp
    pub updated_at: i64,
}

/// Guardian for social recovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guardian {
    /// Guardian identifier (user ID or email)
    pub id: String,
    /// Guardian display name
    pub name: String,
    /// Guardian email
    pub email: String,
    /// Added timestamp
    pub added_at: i64,
}

/// Recovery code (plaintext, given to user)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryCode(String);

impl RecoveryCode {
    /// Generate a new recovery code
    pub fn generate(length: usize) -> Self {
        let mut bytes = vec![0u8; length.div_ceil(2)];
        getrandom::fill(&mut bytes).expect("Failed to generate random bytes");
        let code = hex::encode(&bytes)[..length].to_uppercase();
        Self(code)
    }

    /// Get the code value
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Hash the code for storage
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.0.to_uppercase().as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Format as human-readable (e.g., "ABCD-EFGH-1234")
    pub fn formatted(&self) -> String {
        let chars: Vec<char> = self.0.chars().collect();
        chars
            .chunks(4)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("-")
    }
}

impl std::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecoveryCode(***)")
    }
}

/// Verification code (for email/SMS)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VerificationCode(String);

impl VerificationCode {
    /// Generate a numeric verification code
    pub fn generate(length: usize) -> Self {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("Failed to generate random bytes");
        let num = u64::from_le_bytes(bytes);
        let code = format!("{:0width$}", num % 10u64.pow(length as u32), width = length);
        Self(code)
    }

    /// Get the code value
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Hash the code for storage
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.0.as_bytes());
        hex::encode(hasher.finalize())
    }
}

impl std::fmt::Debug for VerificationCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VerificationCode(***)")
    }
}

/// Recovery manager
pub struct RecoveryManager {
    /// Configuration
    config: RecoveryConfig,
    /// Active recovery requests (request_id -> RecoveryRequest)
    requests: DashMap<String, RecoveryRequest>,
    /// User recovery configurations (user_id -> UserRecoveryConfig)
    user_configs: DashMap<String, UserRecoveryConfig>,
    /// Rate limiting: last request time per user
    last_request: DashMap<String, Instant>,
    /// Rate limit interval
    rate_limit_interval: Duration,
}

impl RecoveryManager {
    /// Create a new recovery manager
    pub fn new(config: RecoveryConfig) -> Self {
        Self {
            config,
            requests: DashMap::new(),
            user_configs: DashMap::new(),
            last_request: DashMap::new(),
            rate_limit_interval: Duration::from_secs(60),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(RecoveryConfig::default())
    }

    /// Generate request ID
    fn generate_request_id() -> String {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("Failed to generate random bytes");
        format!("rec_{}", hex::encode(bytes))
    }

    /// Set up recovery methods for a user
    pub fn configure_user(
        &self,
        user_id: &str,
        email: Option<String>,
        phone: Option<String>,
        guardians: Vec<Guardian>,
        time_locked: bool,
    ) -> Result<Vec<RecoveryCode>> {
        // Generate backup codes
        let backup_codes: Vec<RecoveryCode> = (0..10).map(|_| RecoveryCode::generate(12)).collect();

        let backup_hashes: Vec<String> = backup_codes.iter().map(|c| c.hash()).collect();

        let config = UserRecoveryConfig {
            user_id: user_id.to_string(),
            email: email.map(|e| e.to_lowercase()),
            phone,
            backup_code_hashes: backup_hashes,
            guardians,
            time_locked_enabled: time_locked,
            time_lock_hours: self.config.time_lock_hours,
            updated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        };

        self.user_configs.insert(user_id.to_string(), config);

        Ok(backup_codes)
    }

    /// Get available recovery methods for a user
    pub fn available_methods(&self, user_id: &str) -> Vec<RecoveryMethod> {
        let config = match self.user_configs.get(user_id) {
            Some(c) => c,
            None => return vec![],
        };

        let mut methods = Vec::new();

        if let Some(ref email) = config.email {
            methods.push(RecoveryMethod::Email {
                email: mask_email(email),
            });
        }

        if let Some(ref phone) = config.phone {
            methods.push(RecoveryMethod::Sms {
                phone: mask_phone(phone),
                phone_hint: phone
                    .chars()
                    .rev()
                    .take(4)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect(),
            });
        }

        if !config.backup_code_hashes.is_empty() {
            methods.push(RecoveryMethod::BackupCodes {
                remaining_count: config.backup_code_hashes.len(),
            });
        }

        if config.guardians.len() >= self.config.min_guardians {
            let threshold = ((config.guardians.len() as f32) * self.config.guardian_threshold_ratio)
                .ceil() as usize;
            methods.push(RecoveryMethod::SocialRecovery {
                threshold,
                total_guardians: config.guardians.len(),
            });
        }

        if config.time_locked_enabled {
            methods.push(RecoveryMethod::TimeLocked {
                delay_hours: config.time_lock_hours,
            });
        }

        methods
    }

    /// Initiate recovery via email
    pub fn initiate_email_recovery(
        &self,
        user_id: &str,
        request_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(String, VerificationCode)> {
        // Rate limit check
        self.check_rate_limit(user_id)?;

        // Get user config
        let user_config = self.user_configs.get(user_id).ok_or_else(|| {
            AuthError::InvalidSession("User not configured for recovery".to_string())
        })?;

        let email = user_config
            .email
            .as_ref()
            .ok_or_else(|| AuthError::InvalidSession("Email recovery not configured".to_string()))?
            .clone();

        // Generate verification code
        let code = VerificationCode::generate(self.config.code_length);

        // Create request
        let request_id = Self::generate_request_id();
        let request = RecoveryRequest {
            id: request_id.clone(),
            user_id: user_id.to_string(),
            method: RecoveryMethod::Email { email },
            status: RecoveryStatus::Pending,
            created_at: Instant::now(),
            created_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            expires_in: self.config.code_ttl,
            verification_hash: Some(code.hash()),
            guardian_approvals: vec![],
            time_lock_ends_at: None,
            request_ip,
            user_agent,
            attempts: 0,
            max_attempts: self.config.max_attempts,
        };

        self.requests.insert(request_id.clone(), request);
        self.last_request
            .insert(user_id.to_string(), Instant::now());

        Ok((request_id, code))
    }

    /// Initiate recovery via SMS
    pub fn initiate_sms_recovery(
        &self,
        user_id: &str,
        request_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(String, VerificationCode)> {
        // Rate limit check
        self.check_rate_limit(user_id)?;

        // Get user config
        let user_config = self.user_configs.get(user_id).ok_or_else(|| {
            AuthError::InvalidSession("User not configured for recovery".to_string())
        })?;

        let phone = user_config
            .phone
            .as_ref()
            .ok_or_else(|| AuthError::InvalidSession("SMS recovery not configured".to_string()))?
            .clone();

        // Generate verification code
        let code = VerificationCode::generate(self.config.code_length);

        // Create request
        let request_id = Self::generate_request_id();
        let phone_hint = phone
            .chars()
            .rev()
            .take(4)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        let request = RecoveryRequest {
            id: request_id.clone(),
            user_id: user_id.to_string(),
            method: RecoveryMethod::Sms { phone, phone_hint },
            status: RecoveryStatus::Pending,
            created_at: Instant::now(),
            created_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            expires_in: self.config.code_ttl,
            verification_hash: Some(code.hash()),
            guardian_approvals: vec![],
            time_lock_ends_at: None,
            request_ip,
            user_agent,
            attempts: 0,
            max_attempts: self.config.max_attempts,
        };

        self.requests.insert(request_id.clone(), request);
        self.last_request
            .insert(user_id.to_string(), Instant::now());

        Ok((request_id, code))
    }

    /// Initiate time-locked recovery
    pub fn initiate_time_locked_recovery(
        &self,
        user_id: &str,
        request_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<String> {
        // Rate limit check
        self.check_rate_limit(user_id)?;

        // Get user config
        let user_config = self.user_configs.get(user_id).ok_or_else(|| {
            AuthError::InvalidSession("User not configured for recovery".to_string())
        })?;

        if !user_config.time_locked_enabled {
            return Err(AuthError::InvalidSession(
                "Time-locked recovery not enabled".to_string(),
            ));
        }

        // Calculate time lock end
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let delay_seconds = (user_config.time_lock_hours as i64) * 3600;
        let time_lock_ends_at = now + delay_seconds;

        // Create request
        let request_id = Self::generate_request_id();
        let request = RecoveryRequest {
            id: request_id.clone(),
            user_id: user_id.to_string(),
            method: RecoveryMethod::TimeLocked {
                delay_hours: user_config.time_lock_hours,
            },
            status: RecoveryStatus::TimeLocked,
            created_at: Instant::now(),
            created_timestamp: now,
            expires_in: Duration::from_secs((delay_seconds + 3600) as u64), // Delay + 1 hour buffer
            verification_hash: None,
            guardian_approvals: vec![],
            time_lock_ends_at: Some(time_lock_ends_at),
            request_ip,
            user_agent,
            attempts: 0,
            max_attempts: self.config.max_attempts,
        };

        self.requests.insert(request_id.clone(), request);
        self.last_request
            .insert(user_id.to_string(), Instant::now());

        Ok(request_id)
    }

    /// Initiate social recovery
    pub fn initiate_social_recovery(
        &self,
        user_id: &str,
        request_ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(String, Vec<GuardianApproval>)> {
        // Rate limit check
        self.check_rate_limit(user_id)?;

        // Get user config
        let user_config = self.user_configs.get(user_id).ok_or_else(|| {
            AuthError::InvalidSession("User not configured for recovery".to_string())
        })?;

        if user_config.guardians.len() < self.config.min_guardians {
            return Err(AuthError::InvalidSession(
                "Not enough guardians configured".to_string(),
            ));
        }

        let threshold = ((user_config.guardians.len() as f32)
            * self.config.guardian_threshold_ratio)
            .ceil() as usize;

        // Create guardian approvals
        let guardian_approvals: Vec<GuardianApproval> = user_config
            .guardians
            .iter()
            .map(|g| GuardianApproval {
                guardian_id: g.id.clone(),
                guardian_name: g.name.clone(),
                approved: false,
                approved_at: None,
                approved_from_ip: None,
            })
            .collect();

        // Create request
        let request_id = Self::generate_request_id();
        let request = RecoveryRequest {
            id: request_id.clone(),
            user_id: user_id.to_string(),
            method: RecoveryMethod::SocialRecovery {
                threshold,
                total_guardians: user_config.guardians.len(),
            },
            status: RecoveryStatus::AwaitingGuardians,
            created_at: Instant::now(),
            created_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            expires_in: self.config.request_ttl,
            verification_hash: None,
            guardian_approvals: guardian_approvals.clone(),
            time_lock_ends_at: None,
            request_ip,
            user_agent,
            attempts: 0,
            max_attempts: self.config.max_attempts,
        };

        self.requests.insert(request_id.clone(), request);
        self.last_request
            .insert(user_id.to_string(), Instant::now());

        Ok((request_id, guardian_approvals))
    }

    /// Verify a recovery code (email/SMS)
    pub fn verify_code(&self, request_id: &str, code: &str) -> Result<()> {
        let mut request = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| AuthError::InvalidSession("Recovery request not found".to_string()))?;

        // Check expiration
        if request.is_expired() {
            request.status = RecoveryStatus::Expired;
            return Err(AuthError::SessionExpired);
        }

        // Check attempts
        if request.attempts >= request.max_attempts {
            request.status = RecoveryStatus::Denied;
            return Err(AuthError::RateLimitExceeded(
                "Too many attempts".to_string(),
            ));
        }

        request.attempts += 1;

        // Verify code
        let expected_hash = request
            .verification_hash
            .as_ref()
            .ok_or_else(|| AuthError::Internal("No verification hash".to_string()))?;

        let code_hash = {
            let mut hasher = Sha256::new();
            hasher.update(code.as_bytes());
            hex::encode(hasher.finalize())
        };

        // Constant-time hash comparison: avoid `String ==` which short-circuits
        // on the first differing byte and leaks a timing oracle on the code hash.
        if !ct_eq_hex_hash(&code_hash, expected_hash) {
            return Err(AuthError::Unauthorized(
                "Invalid verification code".to_string(),
            ));
        }

        request.status = RecoveryStatus::Approved;
        Ok(())
    }

    /// Verify a backup code
    pub fn verify_backup_code(&self, user_id: &str, code: &str) -> Result<()> {
        let mut user_config = self
            .user_configs
            .get_mut(user_id)
            .ok_or_else(|| AuthError::InvalidSession("User not configured".to_string()))?;

        let code_hash = {
            let mut hasher = Sha256::new();
            hasher.update(code.to_uppercase().replace("-", "").as_bytes());
            hex::encode(hasher.finalize())
        };

        // Constant-time comparison against every stored hash. We scan all entries
        // (no early `position` short-circuit) and compare decoded bytes with
        // `ct_eq`, so neither the matching index nor a per-byte difference leaks
        // via timing.
        let mut matched_pos: Option<usize> = None;
        for (pos, stored) in user_config.backup_code_hashes.iter().enumerate() {
            if ct_eq_hex_hash(stored, &code_hash) {
                matched_pos = Some(pos);
            }
        }

        if let Some(pos) = matched_pos {
            // Remove used code
            user_config.backup_code_hashes.remove(pos);
            Ok(())
        } else {
            Err(AuthError::Unauthorized("Invalid backup code".to_string()))
        }
    }

    /// Record guardian approval
    pub fn record_guardian_approval(
        &self,
        request_id: &str,
        guardian_id: &str,
        approved_from_ip: Option<String>,
    ) -> Result<bool> {
        let mut request = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| AuthError::InvalidSession("Recovery request not found".to_string()))?;

        // Check expiration
        if request.is_expired() {
            request.status = RecoveryStatus::Expired;
            return Err(AuthError::SessionExpired);
        }

        // Find and update guardian
        let guardian = request
            .guardian_approvals
            .iter_mut()
            .find(|g| g.guardian_id == guardian_id)
            .ok_or_else(|| AuthError::InvalidSession("Guardian not found".to_string()))?;

        if guardian.approved {
            return Err(AuthError::InvalidSession(
                "Guardian already approved".to_string(),
            ));
        }

        guardian.approved = true;
        guardian.approved_at = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        );
        guardian.approved_from_ip = approved_from_ip;

        // Check if we have quorum
        if let RecoveryMethod::SocialRecovery { threshold, .. } = &request.method {
            if request.has_guardian_quorum(*threshold) {
                request.status = RecoveryStatus::Approved;
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Check time-locked recovery status
    pub fn check_time_lock(&self, request_id: &str) -> Result<bool> {
        let mut request = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| AuthError::InvalidSession("Recovery request not found".to_string()))?;

        if request.is_expired() {
            request.status = RecoveryStatus::Expired;
            return Err(AuthError::SessionExpired);
        }

        if request.time_lock_passed() {
            request.status = RecoveryStatus::Approved;
            return Ok(true);
        }

        Ok(false)
    }

    /// Get recovery request status
    pub fn get_request(&self, request_id: &str) -> Option<RecoveryRequest> {
        self.requests.get(request_id).map(|r| r.clone())
    }

    /// Complete recovery (marks as completed)
    pub fn complete_recovery(&self, request_id: &str) -> Result<()> {
        let mut request = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| AuthError::InvalidSession("Recovery request not found".to_string()))?;

        if request.status != RecoveryStatus::Approved {
            return Err(AuthError::InvalidSession(
                "Recovery not approved".to_string(),
            ));
        }

        request.status = RecoveryStatus::Completed;
        Ok(())
    }

    /// Cancel a recovery request
    pub fn cancel_request(&self, request_id: &str) -> Result<()> {
        let mut request = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| AuthError::InvalidSession("Recovery request not found".to_string()))?;

        request.status = RecoveryStatus::Denied;
        Ok(())
    }

    /// Check rate limit
    fn check_rate_limit(&self, user_id: &str) -> Result<()> {
        if let Some(last) = self.last_request.get(user_id) {
            if last.elapsed() < self.rate_limit_interval {
                return Err(AuthError::RateLimitExceeded(format!(
                    "Please wait {} seconds before requesting recovery again",
                    (self.rate_limit_interval - last.elapsed()).as_secs()
                )));
            }
        }
        Ok(())
    }

    /// Cleanup expired requests
    pub fn cleanup_expired(&self) -> usize {
        // Count removals inside `retain` rather than diffing two `len()`
        // snapshots: concurrent inserts between the snapshots can make the
        // second length larger, underflowing the `usize` subtraction.
        let mut removed = 0usize;
        self.requests.retain(|_, request| {
            let keep = !request.is_expired() && request.status != RecoveryStatus::Completed;
            if !keep {
                removed += 1;
            }
            keep
        });
        removed
    }

    /// Regenerate backup codes for a user
    pub fn regenerate_backup_codes(&self, user_id: &str) -> Result<Vec<RecoveryCode>> {
        let mut user_config = self
            .user_configs
            .get_mut(user_id)
            .ok_or_else(|| AuthError::InvalidSession("User not configured".to_string()))?;

        let new_codes: Vec<RecoveryCode> = (0..10).map(|_| RecoveryCode::generate(12)).collect();

        user_config.backup_code_hashes = new_codes.iter().map(|c| c.hash()).collect();

        user_config.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Ok(new_codes)
    }

    /// Get remaining backup codes count
    pub fn backup_codes_remaining(&self, user_id: &str) -> Option<usize> {
        self.user_configs
            .get(user_id)
            .map(|c| c.backup_code_hashes.len())
    }
}

impl Default for RecoveryManager {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// Helper functions

/// Constant-time comparison of two hex-encoded hashes.
///
/// Both inputs are decoded from hex and compared with `subtle::ConstantTimeEq`,
/// so the comparison time is independent of where (or whether) the bytes differ.
fn ct_eq_hex_hash(a_hex: &str, b_hex: &str) -> bool {
    let (a, b) = match (hex::decode(a_hex), hex::decode(b_hex)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return false,
    };
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(&b).into()
}

fn mask_email(email: &str) -> String {
    if let Some((local, domain)) = email.split_once('@') {
        if local.len() <= 2 {
            format!("{}***@{}", &local[..1], domain)
        } else {
            format!("{}***{}@{}", &local[..1], &local[local.len() - 1..], domain)
        }
    } else {
        "***".to_string()
    }
}

fn mask_phone(phone: &str) -> String {
    if phone.len() <= 4 {
        "***".to_string()
    } else {
        format!("***{}", &phone[phone.len() - 4..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_code_generation() {
        let code = RecoveryCode::generate(12);
        assert_eq!(code.as_str().len(), 12);

        let formatted = code.formatted();
        assert!(formatted.contains('-'));
    }

    #[test]
    fn test_verification_code_generation() {
        let code = VerificationCode::generate(6);
        assert_eq!(code.as_str().len(), 6);
        assert!(code.as_str().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_email_masking() {
        assert_eq!(mask_email("user@example.com"), "u***r@example.com");
        assert_eq!(mask_email("ab@example.com"), "a***@example.com");
    }

    #[test]
    fn test_phone_masking() {
        assert_eq!(mask_phone("+12025551234"), "***1234");
        assert_eq!(mask_phone("1234"), "***");
    }

    #[test]
    fn test_configure_user() {
        let manager = RecoveryManager::with_defaults();

        let codes = manager
            .configure_user(
                "user-123",
                Some("user@example.com".to_string()),
                Some("+12025551234".to_string()),
                vec![],
                false,
            )
            .unwrap();

        assert_eq!(codes.len(), 10);

        let methods = manager.available_methods("user-123");
        assert!(methods
            .iter()
            .any(|m| matches!(m, RecoveryMethod::Email { .. })));
        assert!(methods
            .iter()
            .any(|m| matches!(m, RecoveryMethod::Sms { .. })));
        assert!(methods
            .iter()
            .any(|m| matches!(m, RecoveryMethod::BackupCodes { .. })));
    }

    #[test]
    fn test_email_recovery() {
        let manager = RecoveryManager::with_defaults();

        manager
            .configure_user(
                "user-123",
                Some("user@example.com".to_string()),
                None,
                vec![],
                false,
            )
            .unwrap();

        let (request_id, code) = manager
            .initiate_email_recovery("user-123", None, None)
            .unwrap();

        // Verify with correct code
        assert!(manager.verify_code(&request_id, code.as_str()).is_ok());

        // Check status
        let request = manager.get_request(&request_id).unwrap();
        assert_eq!(request.status, RecoveryStatus::Approved);
    }

    #[test]
    fn test_backup_code_verification() {
        let manager = RecoveryManager::with_defaults();

        let codes = manager
            .configure_user("user-123", None, None, vec![], false)
            .unwrap();

        let first_code = codes[0].as_str().to_string();

        // Verify backup code
        assert!(manager.verify_backup_code("user-123", &first_code).is_ok());

        // Same code should fail (already used)
        assert!(manager.verify_backup_code("user-123", &first_code).is_err());

        // Should have 9 codes left
        assert_eq!(manager.backup_codes_remaining("user-123"), Some(9));
    }

    #[test]
    fn test_social_recovery() {
        let manager = RecoveryManager::with_defaults();

        let guardians = vec![
            Guardian {
                id: "g1".to_string(),
                name: "Guardian 1".to_string(),
                email: "g1@example.com".to_string(),
                added_at: 0,
            },
            Guardian {
                id: "g2".to_string(),
                name: "Guardian 2".to_string(),
                email: "g2@example.com".to_string(),
                added_at: 0,
            },
            Guardian {
                id: "g3".to_string(),
                name: "Guardian 3".to_string(),
                email: "g3@example.com".to_string(),
                added_at: 0,
            },
        ];

        manager
            .configure_user("user-123", None, None, guardians, false)
            .unwrap();

        let (request_id, approvals) = manager
            .initiate_social_recovery("user-123", None, None)
            .unwrap();
        assert_eq!(approvals.len(), 3);

        // First approval
        let complete = manager
            .record_guardian_approval(&request_id, "g1", None)
            .unwrap();
        assert!(!complete);

        // Second approval (should reach threshold of 2 for 3 guardians)
        let complete = manager
            .record_guardian_approval(&request_id, "g2", None)
            .unwrap();
        assert!(complete);
    }

    #[test]
    fn test_ct_eq_hex_hash() {
        let a = {
            let mut h = Sha256::new();
            h.update(b"hello");
            hex::encode(h.finalize())
        };
        let b = {
            let mut h = Sha256::new();
            h.update(b"hello");
            hex::encode(h.finalize())
        };
        let c = {
            let mut h = Sha256::new();
            h.update(b"world");
            hex::encode(h.finalize())
        };
        assert!(ct_eq_hex_hash(&a, &b));
        assert!(!ct_eq_hex_hash(&a, &c));
        assert!(!ct_eq_hex_hash("nothex", &a));
    }

    #[test]
    fn test_verify_code_ct_correct_and_wrong() {
        let manager = RecoveryManager::with_defaults();
        manager
            .configure_user(
                "user-ct",
                Some("user@example.com".to_string()),
                None,
                vec![],
                false,
            )
            .unwrap();

        let (request_id, code) = manager
            .initiate_email_recovery("user-ct", None, None)
            .unwrap();

        // Wrong code rejected (constant-time path).
        let wrong = if code.as_str() == "000000" {
            "111111"
        } else {
            "000000"
        };
        assert!(manager.verify_code(&request_id, wrong).is_err());
        // Correct code accepted.
        assert!(manager.verify_code(&request_id, code.as_str()).is_ok());
    }

    #[test]
    fn test_cleanup_expired_no_underflow() {
        let manager = RecoveryManager::with_defaults();
        // No requests: must return 0 without underflow.
        assert_eq!(manager.cleanup_expired(), 0);
        // Calling repeatedly is also safe.
        assert_eq!(manager.cleanup_expired(), 0);
    }
}
