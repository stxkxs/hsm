//! FIPS Audit Logging
//!
//! Implements audit logging required by FIPS 140-3.
//! Records security-relevant events for compliance and forensics.

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Maximum audit log entries to keep in memory
const MAX_LOG_ENTRIES: usize = 10_000;

/// FIPS audit event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FipsAuditEventType {
    // Module lifecycle events
    /// Module initialization started
    ModuleInitStart,
    /// Module initialization completed
    ModuleInitComplete,
    /// Module initialization failed
    ModuleInitFailed,
    /// Module shutdown
    ModuleShutdown,

    // Self-test events
    /// Self-test started
    SelfTestStart,
    /// Self-test passed
    SelfTestPassed,
    /// Self-test failed
    SelfTestFailed,
    /// Conditional self-test triggered
    ConditionalSelfTest,

    // Integrity events
    /// Integrity check started
    IntegrityCheckStart,
    /// Integrity check passed
    IntegrityCheckPassed,
    /// Integrity check failed
    IntegrityCheckFailed,

    // RNG events
    /// DRBG instantiation
    DrbgInstantiate,
    /// DRBG reseed
    DrbgReseed,
    /// DRBG generate
    DrbgGenerate,
    /// DRBG health check failed
    DrbgHealthFailed,

    // Cryptographic operations
    /// Key generation
    KeyGeneration,
    /// Key destruction
    KeyDestruction,
    /// Key import
    KeyImport,
    /// Key export
    KeyExport,
    /// Encryption operation
    Encryption,
    /// Decryption operation
    Decryption,
    /// Signing operation
    Signing,
    /// Verification operation
    Verification,
    /// Hashing operation
    Hashing,
    /// MAC operation
    Mac,
    /// Key derivation
    KeyDerivation,
    /// Key agreement
    KeyAgreement,

    // Security events
    /// Algorithm not approved
    AlgorithmNotApproved,
    /// Key length not approved
    KeyLengthNotApproved,
    /// Operation not allowed
    OperationNotAllowed,
    /// Authentication failure
    AuthenticationFailure,
    /// Access denied
    AccessDenied,
    /// Error state entered
    ErrorStateEntered,
    /// Zeroization performed
    Zeroization,

    // Configuration events
    /// FIPS mode enabled
    FipsModeEnabled,
    /// FIPS mode disabled
    FipsModeDisabled,
    /// Configuration changed
    ConfigurationChanged,

    // Threshold cryptography events
    /// Threshold key generation initiated
    ThresholdKeyGeneration,
    /// Threshold DKG round 1 completed
    ThresholdDkgRound1,
    /// Threshold DKG round 2 completed
    ThresholdDkgRound2,
    /// Threshold DKG protocol completed successfully
    ThresholdDkgComplete,
    /// Threshold signing session started
    ThresholdSigningSessionStart,
    /// Threshold commitment generated
    ThresholdCommitmentGenerated,
    /// Threshold signature share generated
    ThresholdSignatureShareGenerated,
    /// Threshold signature aggregated (signing complete)
    ThresholdSignatureAggregated,
    /// Threshold key refresh initiated
    ThresholdKeyRefresh,
    /// Threshold resharing initiated
    ThresholdResharing,

    // Threshold error events
    /// Insufficient participants for threshold operation
    ThresholdInsufficientParticipants,
    /// Invalid share detected during threshold operation
    ThresholdInvalidShare,
    /// Threshold session timed out
    ThresholdSessionTimeout,
    /// Non-approved threshold scheme attempted in FIPS mode
    ThresholdNonApprovedScheme,
}

impl FipsAuditEventType {
    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::ModuleInitStart => "Module Initialization Started",
            Self::ModuleInitComplete => "Module Initialization Complete",
            Self::ModuleInitFailed => "Module Initialization Failed",
            Self::ModuleShutdown => "Module Shutdown",
            Self::SelfTestStart => "Self-Test Started",
            Self::SelfTestPassed => "Self-Test Passed",
            Self::SelfTestFailed => "Self-Test Failed",
            Self::ConditionalSelfTest => "Conditional Self-Test",
            Self::IntegrityCheckStart => "Integrity Check Started",
            Self::IntegrityCheckPassed => "Integrity Check Passed",
            Self::IntegrityCheckFailed => "Integrity Check Failed",
            Self::DrbgInstantiate => "DRBG Instantiation",
            Self::DrbgReseed => "DRBG Reseed",
            Self::DrbgGenerate => "DRBG Generate",
            Self::DrbgHealthFailed => "DRBG Health Check Failed",
            Self::KeyGeneration => "Key Generation",
            Self::KeyDestruction => "Key Destruction",
            Self::KeyImport => "Key Import",
            Self::KeyExport => "Key Export",
            Self::Encryption => "Encryption",
            Self::Decryption => "Decryption",
            Self::Signing => "Signing",
            Self::Verification => "Verification",
            Self::Hashing => "Hashing",
            Self::Mac => "MAC",
            Self::KeyDerivation => "Key Derivation",
            Self::KeyAgreement => "Key Agreement",
            Self::AlgorithmNotApproved => "Algorithm Not Approved",
            Self::KeyLengthNotApproved => "Key Length Not Approved",
            Self::OperationNotAllowed => "Operation Not Allowed",
            Self::AuthenticationFailure => "Authentication Failure",
            Self::AccessDenied => "Access Denied",
            Self::ErrorStateEntered => "Error State Entered",
            Self::Zeroization => "Zeroization",
            Self::FipsModeEnabled => "FIPS Mode Enabled",
            Self::FipsModeDisabled => "FIPS Mode Disabled",
            Self::ConfigurationChanged => "Configuration Changed",
            // Threshold cryptography events
            Self::ThresholdKeyGeneration => "Threshold Key Generation",
            Self::ThresholdDkgRound1 => "Threshold DKG Round 1",
            Self::ThresholdDkgRound2 => "Threshold DKG Round 2",
            Self::ThresholdDkgComplete => "Threshold DKG Complete",
            Self::ThresholdSigningSessionStart => "Threshold Signing Session Start",
            Self::ThresholdCommitmentGenerated => "Threshold Commitment Generated",
            Self::ThresholdSignatureShareGenerated => "Threshold Signature Share Generated",
            Self::ThresholdSignatureAggregated => "Threshold Signature Aggregated",
            Self::ThresholdKeyRefresh => "Threshold Key Refresh",
            Self::ThresholdResharing => "Threshold Resharing",
            // Threshold error events
            Self::ThresholdInsufficientParticipants => "Threshold Insufficient Participants",
            Self::ThresholdInvalidShare => "Threshold Invalid Share",
            Self::ThresholdSessionTimeout => "Threshold Session Timeout",
            Self::ThresholdNonApprovedScheme => "Threshold Non-Approved Scheme",
        }
    }

    /// Check if this is a security-critical event
    pub fn is_security_critical(&self) -> bool {
        matches!(
            self,
            Self::SelfTestFailed
                | Self::IntegrityCheckFailed
                | Self::DrbgHealthFailed
                | Self::AlgorithmNotApproved
                | Self::KeyLengthNotApproved
                | Self::OperationNotAllowed
                | Self::AuthenticationFailure
                | Self::AccessDenied
                | Self::ErrorStateEntered
                // Threshold security-critical events
                | Self::ThresholdInsufficientParticipants
                | Self::ThresholdInvalidShare
                | Self::ThresholdSessionTimeout
                | Self::ThresholdNonApprovedScheme
        )
    }
}

/// FIPS audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FipsAuditEvent {
    /// Unique event ID
    pub id: u64,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event type
    pub event_type: FipsAuditEventType,
    /// Algorithm used (if applicable)
    pub algorithm: Option<String>,
    /// Key ID (if applicable)
    pub key_id: Option<String>,
    /// Operation result (success/failure)
    pub success: bool,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Additional details
    pub details: Option<String>,
    /// User/operator ID (if applicable)
    pub operator_id: Option<String>,
}

impl FipsAuditEvent {
    /// Create a new audit event
    pub fn new(event_type: FipsAuditEventType) -> Self {
        Self {
            id: 0, // Set by logger
            timestamp: Utc::now(),
            event_type,
            algorithm: None,
            key_id: None,
            success: true,
            error: None,
            details: None,
            operator_id: None,
        }
    }

    /// Builder: set algorithm
    pub fn with_algorithm(mut self, algorithm: &str) -> Self {
        self.algorithm = Some(algorithm.to_string());
        self
    }

    /// Builder: set key ID
    pub fn with_key_id(mut self, key_id: &str) -> Self {
        self.key_id = Some(key_id.to_string());
        self
    }

    /// Builder: set success status
    pub fn with_success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    /// Builder: set error message
    pub fn with_error(mut self, error: &str) -> Self {
        self.error = Some(error.to_string());
        self.success = false;
        self
    }

    /// Builder: set details
    pub fn with_details(mut self, details: &str) -> Self {
        self.details = Some(details.to_string());
        self
    }

    /// Builder: set operator ID
    pub fn with_operator(mut self, operator_id: &str) -> Self {
        self.operator_id = Some(operator_id.to_string());
        self
    }
}

/// FIPS audit log
pub struct FipsAuditLog {
    /// Log entries
    entries: RwLock<VecDeque<FipsAuditEvent>>,
    /// Next event ID
    next_id: AtomicU64,
    /// Maximum entries to keep
    max_entries: usize,
    /// External handler for events
    handler: Option<Arc<dyn FipsAuditHandler + Send + Sync>>,
}

/// Handler trait for external audit processing
pub trait FipsAuditHandler {
    /// Handle an audit event
    fn handle(&self, event: &FipsAuditEvent);

    /// Handle a security-critical event
    fn handle_critical(&self, event: &FipsAuditEvent) {
        self.handle(event);
    }
}

impl FipsAuditLog {
    /// Create a new audit log
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(VecDeque::with_capacity(MAX_LOG_ENTRIES)),
            next_id: AtomicU64::new(1),
            max_entries: MAX_LOG_ENTRIES,
            handler: None,
        }
    }

    /// Create audit log with custom max entries
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(VecDeque::with_capacity(max_entries)),
            next_id: AtomicU64::new(1),
            max_entries,
            handler: None,
        }
    }

    /// Set external handler
    pub fn with_handler(mut self, handler: Arc<dyn FipsAuditHandler + Send + Sync>) -> Self {
        self.handler = Some(handler);
        self
    }

    /// Log an event
    pub fn log(&self, mut event: FipsAuditEvent) {
        // Assign ID
        event.id = self.next_id.fetch_add(1, Ordering::SeqCst);

        // Call external handler if set
        if let Some(ref handler) = self.handler {
            if event.event_type.is_security_critical() {
                handler.handle_critical(&event);
            } else {
                handler.handle(&event);
            }
        }

        // Log to tracing
        if event.success {
            tracing::info!(
                event_id = event.id,
                event_type = ?event.event_type,
                algorithm = ?event.algorithm,
                key_id = ?event.key_id,
                "FIPS audit: {}",
                event.event_type.name()
            );
        } else {
            tracing::warn!(
                event_id = event.id,
                event_type = ?event.event_type,
                algorithm = ?event.algorithm,
                key_id = ?event.key_id,
                error = ?event.error,
                "FIPS audit: {} (FAILED)",
                event.event_type.name()
            );
        }

        // Store in memory
        let mut entries = self.entries.write();
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }
        entries.push_back(event);
    }

    /// Log a simple event
    pub fn log_event(&self, event_type: FipsAuditEventType) {
        self.log(FipsAuditEvent::new(event_type));
    }

    /// Log a success event
    pub fn log_success(&self, event_type: FipsAuditEventType, algorithm: Option<&str>) {
        let mut event = FipsAuditEvent::new(event_type);
        if let Some(alg) = algorithm {
            event = event.with_algorithm(alg);
        }
        self.log(event);
    }

    /// Log a failure event
    pub fn log_failure(&self, event_type: FipsAuditEventType, error: &str) {
        let event = FipsAuditEvent::new(event_type).with_error(error);
        self.log(event);
    }

    /// Get all entries
    pub fn entries(&self) -> Vec<FipsAuditEvent> {
        self.entries.read().iter().cloned().collect()
    }

    /// Get entries since a given ID
    pub fn entries_since(&self, since_id: u64) -> Vec<FipsAuditEvent> {
        self.entries
            .read()
            .iter()
            .filter(|e| e.id > since_id)
            .cloned()
            .collect()
    }

    /// Get entries by type
    pub fn entries_by_type(&self, event_type: FipsAuditEventType) -> Vec<FipsAuditEvent> {
        self.entries
            .read()
            .iter()
            .filter(|e| e.event_type == event_type)
            .cloned()
            .collect()
    }

    /// Get security-critical entries
    pub fn security_critical_entries(&self) -> Vec<FipsAuditEvent> {
        self.entries
            .read()
            .iter()
            .filter(|e| e.event_type.is_security_critical())
            .cloned()
            .collect()
    }

    /// Get failed entries
    pub fn failed_entries(&self) -> Vec<FipsAuditEvent> {
        self.entries
            .read()
            .iter()
            .filter(|e| !e.success)
            .cloned()
            .collect()
    }

    /// Get entry count
    pub fn count(&self) -> usize {
        self.entries.read().len()
    }

    /// Clear all entries
    pub fn clear(&self) {
        self.entries.write().clear();
    }

    /// Export entries to JSON
    pub fn export_json(&self) -> Result<String, String> {
        let entries = self.entries();
        serde_json::to_string_pretty(&entries)
            .map_err(|e| format!("JSON serialization failed: {}", e))
    }

    // ============ Threshold Cryptography Logging Methods ============

    /// Log a threshold key generation event
    pub fn log_threshold_keygen(
        &self,
        scheme: &str,
        threshold: u16,
        total: u16,
        success: bool,
        error: Option<&str>,
    ) {
        let mut event = FipsAuditEvent::new(FipsAuditEventType::ThresholdKeyGeneration)
            .with_algorithm(scheme)
            .with_success(success)
            .with_details(&format!("threshold={}-of-{}", threshold, total));

        if let Some(err) = error {
            event = event.with_error(err);
        }
        self.log(event);
    }

    /// Log a threshold DKG round event
    pub fn log_threshold_dkg_round(&self, round: u8, scheme: &str, participant_count: usize) {
        let event_type = match round {
            1 => FipsAuditEventType::ThresholdDkgRound1,
            2 => FipsAuditEventType::ThresholdDkgRound2,
            _ => FipsAuditEventType::ThresholdDkgComplete,
        };
        let event = FipsAuditEvent::new(event_type)
            .with_algorithm(scheme)
            .with_details(&format!(
                "round={}, participants={}",
                round, participant_count
            ));
        self.log(event);
    }

    /// Log DKG completion
    pub fn log_threshold_dkg_complete(&self, scheme: &str, threshold: u16, total: u16) {
        let event = FipsAuditEvent::new(FipsAuditEventType::ThresholdDkgComplete)
            .with_algorithm(scheme)
            .with_details(&format!("threshold={}-of-{}", threshold, total));
        self.log(event);
    }

    /// Log a threshold signing session start
    pub fn log_threshold_signing_session_start(
        &self,
        session_id: &str,
        scheme: &str,
        participants: &[u16],
    ) {
        let event = FipsAuditEvent::new(FipsAuditEventType::ThresholdSigningSessionStart)
            .with_algorithm(scheme)
            .with_details(&format!(
                "session={}, participants={:?}",
                session_id, participants
            ));
        self.log(event);
    }

    /// Log commitment generation
    pub fn log_threshold_commitment_generated(
        &self,
        session_id: &str,
        participant_id: u16,
        scheme: &str,
    ) {
        let event = FipsAuditEvent::new(FipsAuditEventType::ThresholdCommitmentGenerated)
            .with_algorithm(scheme)
            .with_details(&format!(
                "session={}, participant={}",
                session_id, participant_id
            ));
        self.log(event);
    }

    /// Log signature share generation
    pub fn log_threshold_signature_share_generated(
        &self,
        session_id: &str,
        participant_id: u16,
        scheme: &str,
    ) {
        let event = FipsAuditEvent::new(FipsAuditEventType::ThresholdSignatureShareGenerated)
            .with_algorithm(scheme)
            .with_details(&format!(
                "session={}, participant={}",
                session_id, participant_id
            ));
        self.log(event);
    }

    /// Log signature aggregation (signing complete)
    pub fn log_threshold_signature_aggregated(
        &self,
        session_id: &str,
        scheme: &str,
        participants: &[u16],
        success: bool,
        error: Option<&str>,
    ) {
        let mut event = FipsAuditEvent::new(FipsAuditEventType::ThresholdSignatureAggregated)
            .with_algorithm(scheme)
            .with_success(success)
            .with_details(&format!(
                "session={}, participants={:?}",
                session_id, participants
            ));

        if let Some(err) = error {
            event = event.with_error(err);
        }
        self.log(event);
    }

    /// Log key refresh event
    pub fn log_threshold_key_refresh(&self, scheme: &str, success: bool, error: Option<&str>) {
        let mut event = FipsAuditEvent::new(FipsAuditEventType::ThresholdKeyRefresh)
            .with_algorithm(scheme)
            .with_success(success);

        if let Some(err) = error {
            event = event.with_error(err);
        }
        self.log(event);
    }

    /// Log resharing event
    pub fn log_threshold_resharing(
        &self,
        scheme: &str,
        old_threshold: u16,
        new_threshold: u16,
        success: bool,
        error: Option<&str>,
    ) {
        let mut event = FipsAuditEvent::new(FipsAuditEventType::ThresholdResharing)
            .with_algorithm(scheme)
            .with_success(success)
            .with_details(&format!(
                "old_threshold={}, new_threshold={}",
                old_threshold, new_threshold
            ));

        if let Some(err) = error {
            event = event.with_error(err);
        }
        self.log(event);
    }

    /// Log insufficient participants error
    pub fn log_threshold_insufficient_participants(
        &self,
        scheme: &str,
        required: usize,
        provided: usize,
    ) {
        let event = FipsAuditEvent::new(FipsAuditEventType::ThresholdInsufficientParticipants)
            .with_algorithm(scheme)
            .with_error(&format!(
                "Required {} participants, got {}",
                required, provided
            ));
        self.log(event);
    }

    /// Log invalid share error
    pub fn log_threshold_invalid_share(&self, scheme: &str, participant_id: u16, reason: &str) {
        let event = FipsAuditEvent::new(FipsAuditEventType::ThresholdInvalidShare)
            .with_algorithm(scheme)
            .with_error(&format!(
                "Invalid share from participant {}: {}",
                participant_id, reason
            ));
        self.log(event);
    }

    /// Log session timeout error
    pub fn log_threshold_session_timeout(&self, session_id: &str, scheme: &str, timeout_ms: u64) {
        let event = FipsAuditEvent::new(FipsAuditEventType::ThresholdSessionTimeout)
            .with_algorithm(scheme)
            .with_error(&format!(
                "Session {} timed out after {}ms",
                session_id, timeout_ms
            ));
        self.log(event);
    }

    /// Log non-approved scheme attempt in FIPS mode
    pub fn log_threshold_non_approved_scheme(&self, scheme: &str) {
        let event = FipsAuditEvent::new(FipsAuditEventType::ThresholdNonApprovedScheme)
            .with_algorithm(scheme)
            .with_error(&format!(
                "Attempted to use non-FIPS-approved threshold scheme: {}",
                scheme
            ));
        self.log(event);
    }
}

impl Default for FipsAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracing-based audit handler
pub struct TracingAuditHandler;

impl FipsAuditHandler for TracingAuditHandler {
    fn handle(&self, event: &FipsAuditEvent) {
        tracing::info!(
            target: "fips_audit",
            event_id = event.id,
            event_type = %event.event_type.name(),
            success = event.success,
            "FIPS Audit Event"
        );
    }

    fn handle_critical(&self, event: &FipsAuditEvent) {
        tracing::error!(
            target: "fips_audit_critical",
            event_id = event.id,
            event_type = %event.event_type.name(),
            error = ?event.error,
            "FIPS Critical Security Event"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_creation() {
        let log = FipsAuditLog::new();
        assert_eq!(log.count(), 0);
    }

    #[test]
    fn test_log_event() {
        let log = FipsAuditLog::new();

        log.log_event(FipsAuditEventType::ModuleInitStart);
        log.log_event(FipsAuditEventType::SelfTestStart);
        log.log_event(FipsAuditEventType::SelfTestPassed);
        log.log_event(FipsAuditEventType::ModuleInitComplete);

        assert_eq!(log.count(), 4);

        let entries = log.entries();
        assert_eq!(entries[0].event_type, FipsAuditEventType::ModuleInitStart);
        assert_eq!(entries[1].event_type, FipsAuditEventType::SelfTestStart);
    }

    #[test]
    fn test_log_success_failure() {
        let log = FipsAuditLog::new();

        log.log_success(FipsAuditEventType::KeyGeneration, Some("AES-256"));
        log.log_failure(FipsAuditEventType::KeyGeneration, "Invalid key length");

        let entries = log.entries();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].success);
        assert!(!entries[1].success);
        assert!(entries[1].error.is_some());
    }

    #[test]
    fn test_entries_by_type() {
        let log = FipsAuditLog::new();

        log.log_event(FipsAuditEventType::KeyGeneration);
        log.log_event(FipsAuditEventType::Signing);
        log.log_event(FipsAuditEventType::KeyGeneration);
        log.log_event(FipsAuditEventType::Encryption);

        let key_gen_entries = log.entries_by_type(FipsAuditEventType::KeyGeneration);
        assert_eq!(key_gen_entries.len(), 2);
    }

    #[test]
    fn test_security_critical_entries() {
        let log = FipsAuditLog::new();

        log.log_event(FipsAuditEventType::KeyGeneration);
        log.log_failure(FipsAuditEventType::SelfTestFailed, "KAT failed");
        log.log_event(FipsAuditEventType::Signing);
        log.log_failure(
            FipsAuditEventType::AlgorithmNotApproved,
            "ChaCha20 not approved",
        );

        let critical = log.security_critical_entries();
        assert_eq!(critical.len(), 2);
    }

    #[test]
    fn test_max_entries() {
        let log = FipsAuditLog::with_max_entries(3);

        log.log_event(FipsAuditEventType::KeyGeneration);
        log.log_event(FipsAuditEventType::Signing);
        log.log_event(FipsAuditEventType::Encryption);
        log.log_event(FipsAuditEventType::Decryption);

        // Should only have 3 entries, oldest removed
        assert_eq!(log.count(), 3);

        let entries = log.entries();
        assert_eq!(entries[0].event_type, FipsAuditEventType::Signing);
    }

    #[test]
    fn test_entries_since() {
        let log = FipsAuditLog::new();

        log.log_event(FipsAuditEventType::KeyGeneration);
        log.log_event(FipsAuditEventType::Signing);

        let second_id = log.entries()[1].id;

        log.log_event(FipsAuditEventType::Encryption);
        log.log_event(FipsAuditEventType::Decryption);

        let new_entries = log.entries_since(second_id);
        assert_eq!(new_entries.len(), 2);
        assert_eq!(new_entries[0].event_type, FipsAuditEventType::Encryption);
    }

    #[test]
    fn test_event_builder() {
        let event = FipsAuditEvent::new(FipsAuditEventType::Signing)
            .with_algorithm("Ed25519")
            .with_key_id("key-123")
            .with_operator("admin")
            .with_details("Signing transaction");

        assert!(event.success);
        assert_eq!(event.algorithm, Some("Ed25519".to_string()));
        assert_eq!(event.key_id, Some("key-123".to_string()));
        assert_eq!(event.operator_id, Some("admin".to_string()));
    }

    #[test]
    fn test_event_type_security_critical() {
        assert!(FipsAuditEventType::SelfTestFailed.is_security_critical());
        assert!(FipsAuditEventType::IntegrityCheckFailed.is_security_critical());
        assert!(FipsAuditEventType::AlgorithmNotApproved.is_security_critical());
        assert!(!FipsAuditEventType::KeyGeneration.is_security_critical());
        assert!(!FipsAuditEventType::Signing.is_security_critical());
    }

    #[test]
    fn test_export_json() {
        let log = FipsAuditLog::new();

        log.log_success(FipsAuditEventType::KeyGeneration, Some("AES-256"));
        log.log_event(FipsAuditEventType::ModuleInitComplete);

        let json = log.export_json().unwrap();
        assert!(json.contains("KeyGeneration"));
        assert!(json.contains("AES-256"));
    }

    #[test]
    fn test_clear() {
        let log = FipsAuditLog::new();

        log.log_event(FipsAuditEventType::KeyGeneration);
        log.log_event(FipsAuditEventType::Signing);
        assert_eq!(log.count(), 2);

        log.clear();
        assert_eq!(log.count(), 0);
    }

    // ============ Threshold Audit Event Tests ============

    #[test]
    fn test_threshold_keygen_logging() {
        let log = FipsAuditLog::new();

        log.log_threshold_keygen("FROST-Ed25519", 2, 3, true, None);

        let entries = log.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].event_type,
            FipsAuditEventType::ThresholdKeyGeneration
        );
        assert!(entries[0].success);
        assert_eq!(entries[0].algorithm, Some("FROST-Ed25519".to_string()));
        assert!(entries[0].details.as_ref().unwrap().contains("2-of-3"));
    }

    #[test]
    fn test_threshold_dkg_round_logging() {
        let log = FipsAuditLog::new();

        log.log_threshold_dkg_round(1, "Threshold-ECDSA-P256", 5);
        log.log_threshold_dkg_round(2, "Threshold-ECDSA-P256", 5);
        log.log_threshold_dkg_complete("Threshold-ECDSA-P256", 3, 5);

        let entries = log.entries();
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0].event_type,
            FipsAuditEventType::ThresholdDkgRound1
        );
        assert_eq!(
            entries[1].event_type,
            FipsAuditEventType::ThresholdDkgRound2
        );
        assert_eq!(
            entries[2].event_type,
            FipsAuditEventType::ThresholdDkgComplete
        );
    }

    #[test]
    fn test_threshold_signing_session_logging() {
        let log = FipsAuditLog::new();

        let session_id = "session-123";
        let participants = vec![1u16, 2u16, 3u16];

        log.log_threshold_signing_session_start(session_id, "FROST-Ed25519", &participants);
        log.log_threshold_commitment_generated(session_id, 1, "FROST-Ed25519");
        log.log_threshold_signature_share_generated(session_id, 1, "FROST-Ed25519");
        log.log_threshold_signature_aggregated(
            session_id,
            "FROST-Ed25519",
            &participants,
            true,
            None,
        );

        let entries = log.entries();
        assert_eq!(entries.len(), 4);
        assert_eq!(
            entries[0].event_type,
            FipsAuditEventType::ThresholdSigningSessionStart
        );
        assert_eq!(
            entries[1].event_type,
            FipsAuditEventType::ThresholdCommitmentGenerated
        );
        assert_eq!(
            entries[2].event_type,
            FipsAuditEventType::ThresholdSignatureShareGenerated
        );
        assert_eq!(
            entries[3].event_type,
            FipsAuditEventType::ThresholdSignatureAggregated
        );
    }

    #[test]
    fn test_threshold_error_events_are_security_critical() {
        assert!(FipsAuditEventType::ThresholdInsufficientParticipants.is_security_critical());
        assert!(FipsAuditEventType::ThresholdInvalidShare.is_security_critical());
        assert!(FipsAuditEventType::ThresholdSessionTimeout.is_security_critical());
        assert!(FipsAuditEventType::ThresholdNonApprovedScheme.is_security_critical());

        // Regular threshold events are not security critical
        assert!(!FipsAuditEventType::ThresholdKeyGeneration.is_security_critical());
        assert!(!FipsAuditEventType::ThresholdSignatureAggregated.is_security_critical());
    }

    #[test]
    fn test_threshold_error_logging() {
        let log = FipsAuditLog::new();

        log.log_threshold_insufficient_participants("FROST-Ed25519", 3, 2);
        log.log_threshold_invalid_share("FROST-Ed25519", 2, "Invalid commitment proof");
        log.log_threshold_session_timeout("session-123", "FROST-Ed25519", 30000);
        log.log_threshold_non_approved_scheme("Threshold-ECDSA-secp256k1");

        let critical = log.security_critical_entries();
        assert_eq!(critical.len(), 4);

        let failed = log.failed_entries();
        assert_eq!(failed.len(), 4);
    }

    #[test]
    fn test_threshold_key_refresh_logging() {
        let log = FipsAuditLog::new();

        log.log_threshold_key_refresh("FROST-Ed25519", true, None);
        log.log_threshold_key_refresh("FROST-Ed25519", false, Some("Network failure"));

        let entries = log.entries();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].success);
        assert!(!entries[1].success);
        assert!(entries[1]
            .error
            .as_ref()
            .unwrap()
            .contains("Network failure"));
    }

    #[test]
    fn test_threshold_resharing_logging() {
        let log = FipsAuditLog::new();

        log.log_threshold_resharing("Threshold-ECDSA-P256", 2, 3, true, None);

        let entries = log.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].event_type,
            FipsAuditEventType::ThresholdResharing
        );
        let details = entries[0].details.as_ref().unwrap();
        assert!(details.contains("old_threshold=2"));
        assert!(details.contains("new_threshold=3"));
    }
}
