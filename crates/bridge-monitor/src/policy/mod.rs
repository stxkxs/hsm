//! Policy enforcement for bridge security

use crate::config::PolicyConfig;
use crate::correlation::CorrelatedEvent;
use crate::detection::{AnomalyType, DetectionResult, Severity};
use crate::error::{BridgeError, Result};
use bigdecimal::BigDecimal;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Policy action to take
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Allow the transaction
    Allow,
    /// Require manual approval
    RequireApproval {
        required_approvers: u32,
        reason: String,
    },
    /// Time lock the transaction
    TimeLock { delay_secs: u64, reason: String },
    /// Block the transaction
    Block { reason: String },
    /// Pause the bridge
    PauseBridge { reason: String },
    /// Alert only (no blocking action)
    AlertOnly { severity: Severity, message: String },
}

impl PolicyAction {
    /// Check if this action allows the transaction
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow | Self::AlertOnly { .. })
    }

    /// Check if this action blocks the transaction
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Block { .. } | Self::PauseBridge { .. })
    }
}

/// Pending approval record
#[derive(Debug, Clone)]
pub struct PendingApproval {
    /// Approval ID
    pub id: String,
    /// Event requiring approval
    pub event: CorrelatedEvent,
    /// Reason for approval
    pub reason: String,
    /// Required approvers
    pub required_approvers: u32,
    /// Current approvals
    pub approvals: Vec<Approval>,
    /// Creation time
    pub created_at: Instant,
    /// Expiration
    pub expires_at: Instant,
    /// Status
    pub status: ApprovalStatus,
}

impl PendingApproval {
    /// Check if enough approvals received
    pub fn is_approved(&self) -> bool {
        self.approvals.len() as u32 >= self.required_approvers
    }

    /// Check if expired
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// Approval record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    /// Approver ID
    pub approver_id: String,
    /// Approval time
    pub approved_at: i64,
    /// Approver IP
    pub ip_address: Option<String>,
    /// Comment
    pub comment: Option<String>,
}

/// Approval status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// Waiting for approvals
    Pending,
    /// Approved
    Approved,
    /// Rejected
    Rejected,
    /// Expired
    Expired,
}

/// Bridge policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgePolicy {
    /// Maximum single withdrawal (percentage of TVL)
    pub max_withdrawal_pct: f64,
    /// Maximum hourly volume
    pub hourly_limit: Option<BigDecimal>,
    /// Require N approvals above threshold
    pub approval_threshold: Option<BigDecimal>,
    /// Number of required approvers
    pub required_approvers: u32,
    /// Auto-pause conditions
    pub pause_on_anomaly: bool,
    /// Pause on imbalance threshold
    pub pause_on_imbalance_pct: Option<f64>,
    /// Time lock threshold
    pub time_lock_threshold: Option<BigDecimal>,
    /// Time lock duration (seconds)
    pub time_lock_duration_secs: u64,
}

impl Default for BridgePolicy {
    fn default() -> Self {
        Self {
            max_withdrawal_pct: 5.0,
            hourly_limit: None,
            approval_threshold: None,
            required_approvers: 2,
            pause_on_anomaly: true,
            pause_on_imbalance_pct: Some(20.0),
            time_lock_threshold: None,
            time_lock_duration_secs: 3600,
        }
    }
}

/// Policy enforcer
pub struct PolicyEnforcer {
    /// Configuration
    config: PolicyConfig,
    /// Bridge paused flag
    paused: AtomicBool,
    /// Pause reason
    pause_reason: parking_lot::RwLock<Option<String>>,
    /// Pending approvals
    pending_approvals: DashMap<String, PendingApproval>,
    /// Time-locked transactions
    time_locked: DashMap<String, TimeLockEntry>,
    /// Whitelisted addresses
    whitelist: DashMap<String, ()>,
    /// Blacklisted addresses
    blacklist: DashMap<String, ()>,
    /// Approval timeout
    approval_timeout: Duration,
}

/// Time lock entry
#[derive(Debug, Clone)]
struct TimeLockEntry {
    event: CorrelatedEvent,
    release_at: Instant,
    reason: String,
}

impl PolicyEnforcer {
    /// Create a new policy enforcer
    pub fn new(config: PolicyConfig) -> Self {
        let whitelist: DashMap<String, ()> = config
            .whitelist
            .iter()
            .map(|a| (a.to_lowercase(), ()))
            .collect();

        let blacklist: DashMap<String, ()> = config
            .blacklist
            .iter()
            .map(|a| (a.to_lowercase(), ()))
            .collect();

        Self {
            config,
            paused: AtomicBool::new(false),
            pause_reason: parking_lot::RwLock::new(None),
            pending_approvals: DashMap::new(),
            time_locked: DashMap::new(),
            whitelist,
            blacklist,
            approval_timeout: Duration::from_secs(3600),
        }
    }

    /// Check if bridge is paused
    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// Pause the bridge
    pub fn pause(&self, reason: &str) {
        self.paused.store(true, Ordering::SeqCst);
        *self.pause_reason.write() = Some(reason.to_string());
        tracing::warn!("Bridge paused: {}", reason);
    }

    /// Unpause the bridge
    pub fn unpause(&self) {
        self.paused.store(false, Ordering::SeqCst);
        *self.pause_reason.write() = None;
        tracing::info!("Bridge unpaused");
    }

    /// Get pause reason
    pub fn pause_reason(&self) -> Option<String> {
        self.pause_reason.read().clone()
    }

    /// Add address to whitelist
    pub fn add_to_whitelist(&self, address: &str) {
        self.whitelist.insert(address.to_lowercase(), ());
    }

    /// Remove address from whitelist
    pub fn remove_from_whitelist(&self, address: &str) {
        self.whitelist.remove(&address.to_lowercase());
    }

    /// Check if address is whitelisted
    pub fn is_whitelisted(&self, address: &str) -> bool {
        self.whitelist.contains_key(&address.to_lowercase())
    }

    /// Add address to blacklist
    pub fn add_to_blacklist(&self, address: &str) {
        self.blacklist.insert(address.to_lowercase(), ());
    }

    /// Check if address is blacklisted
    pub fn is_blacklisted(&self, address: &str) -> bool {
        self.blacklist.contains_key(&address.to_lowercase())
    }

    /// Evaluate policy for an event
    pub async fn evaluate(
        &self,
        event: &CorrelatedEvent,
        detection: &DetectionResult,
    ) -> Result<PolicyAction> {
        // Check if bridge is paused
        if self.is_paused() {
            return Ok(PolicyAction::Block {
                reason: self
                    .pause_reason()
                    .unwrap_or_else(|| "Bridge is paused".to_string()),
            });
        }

        // Check blacklist
        if self.is_blacklisted(&event.source_event.from_address)
            || self.is_blacklisted(&event.source_event.to_address)
        {
            return Ok(PolicyAction::Block {
                reason: "Address is blacklisted".to_string(),
            });
        }

        // Check whitelist (bypass other checks)
        if self.is_whitelisted(&event.source_event.from_address) {
            return Ok(PolicyAction::Allow);
        }

        // Handle anomalies based on type and severity
        if detection.is_anomaly {
            return self.handle_anomaly(event, detection).await;
        }

        // Check if approval is required based on amount
        if let Some(ref threshold) = self.config.approval_threshold {
            if event.amount() > threshold {
                return Ok(PolicyAction::RequireApproval {
                    required_approvers: self.config.required_approvers,
                    reason: format!(
                        "Transaction amount {} exceeds threshold {}",
                        event.amount(),
                        threshold
                    ),
                });
            }
        }

        // Check time lock
        if self.config.time_lock_secs > 0 {
            return Ok(PolicyAction::TimeLock {
                delay_secs: self.config.time_lock_secs,
                reason: "Standard time lock for large transactions".to_string(),
            });
        }

        Ok(PolicyAction::Allow)
    }

    /// Handle anomaly according to policy
    async fn handle_anomaly(
        &self,
        event: &CorrelatedEvent,
        detection: &DetectionResult,
    ) -> Result<PolicyAction> {
        let anomaly_type = detection.anomaly_type.as_ref().unwrap();

        match detection.severity {
            Severity::Critical => {
                // Critical anomalies may pause the bridge
                if self.config.auto_pause_on_anomaly {
                    Ok(PolicyAction::PauseBridge {
                        reason: detection.description.clone(),
                    })
                } else {
                    Ok(PolicyAction::Block {
                        reason: detection.description.clone(),
                    })
                }
            }
            Severity::High => match anomaly_type {
                AnomalyType::LargeWithdrawal => {
                    // A large withdrawal can be delayed instead of requiring a
                    // manual approval when a time lock is configured, giving
                    // operators a window to react before funds move.
                    if self.config.time_lock_secs > 0 {
                        Ok(PolicyAction::TimeLock {
                            delay_secs: self.config.time_lock_secs,
                            reason: format!(
                                "Large withdrawal of {} held for review (correlation {})",
                                event.amount(),
                                event.id
                            ),
                        })
                    } else {
                        Ok(PolicyAction::RequireApproval {
                            required_approvers: self.config.required_approvers,
                            reason: format!("{} (correlation {})", detection.description, event.id),
                        })
                    }
                }
                AnomalyType::BlacklistedAddress => Ok(PolicyAction::Block {
                    reason: "Blacklisted address".to_string(),
                }),
                _ => Ok(PolicyAction::RequireApproval {
                    required_approvers: self.config.required_approvers,
                    reason: format!("{} (correlation {})", detection.description, event.id),
                }),
            },
            Severity::Medium => Ok(PolicyAction::AlertOnly {
                severity: Severity::Medium,
                message: detection.description.clone(),
            }),
            Severity::Low => Ok(PolicyAction::Allow),
        }
    }

    /// Execute a policy action for a correlated event.
    ///
    /// A [`PolicyAction::TimeLock`] enqueues the event into the time-lock
    /// queue; it is later released by [`PolicyEnforcer::release_expired`].
    pub async fn execute(&self, event: &CorrelatedEvent, action: PolicyAction) -> Result<()> {
        match action {
            PolicyAction::Allow => {
                tracing::debug!("Transaction allowed");
            }
            PolicyAction::RequireApproval {
                required_approvers,
                reason,
            } => {
                tracing::info!(
                    "Approval required: {} ({} approvers)",
                    reason,
                    required_approvers
                );
            }
            PolicyAction::TimeLock { delay_secs, reason } => {
                self.time_lock(event, delay_secs, reason);
            }
            PolicyAction::Block { reason } => {
                tracing::warn!("Transaction blocked: {}", reason);
            }
            PolicyAction::PauseBridge { reason } => {
                self.pause(&reason);
            }
            PolicyAction::AlertOnly { severity, message } => match severity {
                Severity::Critical | Severity::High => {
                    tracing::warn!("Alert: {}", message);
                }
                Severity::Medium => {
                    tracing::info!("Alert: {}", message);
                }
                Severity::Low => {
                    tracing::debug!("Alert: {}", message);
                }
            },
        }

        Ok(())
    }

    /// Enqueue a correlated event into the time-lock queue.
    ///
    /// The entry is released once `delay_secs` have elapsed, observable via
    /// [`PolicyEnforcer::release_expired`]. Keyed by correlation ID so the
    /// most recent lock for an event wins.
    pub fn time_lock(&self, event: &CorrelatedEvent, delay_secs: u64, reason: String) {
        let release_at = Instant::now() + Duration::from_secs(delay_secs);
        tracing::info!(
            "Time locking correlation {} for {} seconds: {}",
            event.id,
            delay_secs,
            reason
        );
        self.time_locked.insert(
            event.id.clone(),
            TimeLockEntry {
                event: event.clone(),
                release_at,
                reason,
            },
        );
    }

    /// Check whether a correlation is currently time-locked (not yet released).
    pub fn is_time_locked(&self, correlation_id: &str) -> bool {
        self.time_locked
            .get(correlation_id)
            .map(|e| Instant::now() < e.release_at)
            .unwrap_or(false)
    }

    /// Number of transactions currently held in the time-lock queue.
    pub fn pending_time_locked(&self) -> usize {
        self.time_locked.len()
    }

    /// Release every time-locked entry whose `release_at` is at or before `now`.
    ///
    /// Released entries are removed from the queue and returned so callers can
    /// resume processing of the previously delayed transactions. `now` is
    /// passed explicitly so callers (and tests) control the clock.
    pub fn release_expired(&self, now: Instant) -> Vec<CorrelatedEvent> {
        let ready: Vec<String> = self
            .time_locked
            .iter()
            .filter(|entry| now >= entry.release_at)
            .map(|entry| entry.key().clone())
            .collect();

        let mut released = Vec::with_capacity(ready.len());
        for id in ready {
            if let Some((_, entry)) = self.time_locked.remove(&id) {
                tracing::info!(
                    "Releasing time-locked correlation {}: {}",
                    entry.event.id,
                    entry.reason
                );
                released.push(entry.event);
            }
        }
        released
    }

    /// Request approval for an event
    pub fn request_approval(
        &self,
        event: CorrelatedEvent,
        reason: String,
        required_approvers: u32,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let now = Instant::now();

        let pending = PendingApproval {
            id: id.clone(),
            event,
            reason,
            required_approvers,
            approvals: vec![],
            created_at: now,
            expires_at: now + self.approval_timeout,
            status: ApprovalStatus::Pending,
        };

        self.pending_approvals.insert(id.clone(), pending);
        id
    }

    /// Record an approval
    pub fn record_approval(
        &self,
        approval_id: &str,
        approver_id: &str,
        ip_address: Option<String>,
        comment: Option<String>,
    ) -> Result<bool> {
        let mut pending = self
            .pending_approvals
            .get_mut(approval_id)
            .ok_or_else(|| BridgeError::Internal("Approval not found".to_string()))?;

        if pending.is_expired() {
            pending.status = ApprovalStatus::Expired;
            return Err(BridgeError::Internal("Approval expired".to_string()));
        }

        // Check if already approved by this approver
        if pending
            .approvals
            .iter()
            .any(|a| a.approver_id == approver_id)
        {
            return Err(BridgeError::Internal(
                "Already approved by this approver".to_string(),
            ));
        }

        pending.approvals.push(Approval {
            approver_id: approver_id.to_string(),
            approved_at: chrono::Utc::now().timestamp(),
            ip_address,
            comment,
        });

        let is_approved = pending.is_approved();
        if is_approved {
            pending.status = ApprovalStatus::Approved;
        }

        Ok(is_approved)
    }

    /// Reject an approval request
    pub fn reject_approval(&self, approval_id: &str) -> Result<()> {
        let mut pending = self
            .pending_approvals
            .get_mut(approval_id)
            .ok_or_else(|| BridgeError::Internal("Approval not found".to_string()))?;

        pending.status = ApprovalStatus::Rejected;
        Ok(())
    }

    /// Get pending approval
    pub fn get_pending_approval(&self, approval_id: &str) -> Option<PendingApproval> {
        self.pending_approvals.get(approval_id).map(|p| p.clone())
    }

    /// Get all pending approvals
    pub fn all_pending_approvals(&self) -> Vec<PendingApproval> {
        self.pending_approvals.iter().map(|e| e.clone()).collect()
    }

    /// Cleanup expired approvals
    pub fn cleanup_expired(&self) -> usize {
        let mut count = 0;
        self.pending_approvals.iter_mut().for_each(|mut entry| {
            if entry.is_expired() && entry.status == ApprovalStatus::Pending {
                entry.status = ApprovalStatus::Expired;
                count += 1;
            }
        });
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlation::CorrelationStatus;
    use crate::watcher::{BridgeEvent, EventType};
    use std::str::FromStr;

    fn test_config() -> PolicyConfig {
        PolicyConfig {
            auto_pause_on_anomaly: true,
            approval_threshold: Some(BigDecimal::from_str("10000").unwrap()),
            required_approvers: 2,
            time_lock_secs: 0,
            whitelist: vec![],
            blacklist: vec!["0xbad".to_string()],
        }
    }

    fn test_event(amount: &str) -> CorrelatedEvent {
        let source = BridgeEvent::new(
            "ethereum",
            12345,
            "0xdep",
            EventType::Deposit,
            "USDC",
            BigDecimal::from_str(amount).unwrap(),
            "0xsender",
            "0xrecipient",
        );

        CorrelatedEvent {
            id: "test-1".to_string(),
            source_event: source,
            destination_event: None,
            status: CorrelationStatus::Pending,
            created_at: chrono::Utc::now().timestamp(),
            completed_at: None,
            latency_secs: None,
        }
    }

    #[tokio::test]
    async fn test_normal_transaction() {
        let enforcer = PolicyEnforcer::new(test_config());
        let event = test_event("1000");
        let detection = DetectionResult::normal();

        let action = enforcer.evaluate(&event, &detection).await.unwrap();
        assert_eq!(action, PolicyAction::Allow);
    }

    #[tokio::test]
    async fn test_large_transaction_requires_approval() {
        let enforcer = PolicyEnforcer::new(test_config());
        let event = test_event("50000");
        let detection = DetectionResult::normal();

        let action = enforcer.evaluate(&event, &detection).await.unwrap();
        assert!(matches!(action, PolicyAction::RequireApproval { .. }));
    }

    #[tokio::test]
    async fn test_blacklisted_address() {
        let enforcer = PolicyEnforcer::new(test_config());
        let mut event = test_event("1000");
        event.source_event.from_address = "0xbad".to_string();
        let detection = DetectionResult::normal();

        let action = enforcer.evaluate(&event, &detection).await.unwrap();
        assert!(matches!(action, PolicyAction::Block { .. }));
    }

    #[tokio::test]
    async fn test_bridge_pause() {
        let enforcer = PolicyEnforcer::new(test_config());

        enforcer.pause("Test pause");
        assert!(enforcer.is_paused());

        let event = test_event("1000");
        let detection = DetectionResult::normal();
        let action = enforcer.evaluate(&event, &detection).await.unwrap();

        assert!(matches!(action, PolicyAction::Block { .. }));

        enforcer.unpause();
        assert!(!enforcer.is_paused());
    }

    #[tokio::test]
    async fn test_time_lock_release() {
        let enforcer = PolicyEnforcer::new(test_config());
        let event = test_event("50000");

        // Lock the event for 60 seconds.
        enforcer
            .execute(
                &event,
                PolicyAction::TimeLock {
                    delay_secs: 60,
                    reason: "test lock".to_string(),
                },
            )
            .await
            .unwrap();

        assert_eq!(enforcer.pending_time_locked(), 1);
        assert!(enforcer.is_time_locked(&event.id));

        // Before release_at: nothing is released and the entry remains.
        let released = enforcer.release_expired(Instant::now());
        assert!(released.is_empty());
        assert_eq!(enforcer.pending_time_locked(), 1);

        // At/after release_at: the entry is released and removed.
        let after = Instant::now() + Duration::from_secs(61);
        let released = enforcer.release_expired(after);
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].id, event.id);
        assert_eq!(enforcer.pending_time_locked(), 0);
        assert!(!enforcer.is_time_locked(&event.id));
    }

    #[tokio::test]
    async fn test_time_lock_secs_config_changes_behavior() {
        // A High-severity large withdrawal with a configured time lock is
        // delayed (TimeLock); with no time lock it requires approval. This
        // proves PolicyConfig::time_lock_secs actually drives the decision.
        let detection = DetectionResult::anomaly(
            AnomalyType::LargeWithdrawal,
            Severity::High,
            0.9,
            "Large withdrawal".to_string(),
        );
        let event = test_event("50000");

        let mut cfg = test_config();
        cfg.time_lock_secs = 0;
        let enforcer = PolicyEnforcer::new(cfg);
        let action = enforcer.evaluate(&event, &detection).await.unwrap();
        assert!(matches!(action, PolicyAction::RequireApproval { .. }));

        let mut cfg = test_config();
        cfg.time_lock_secs = 120;
        let enforcer = PolicyEnforcer::new(cfg);
        let action = enforcer.evaluate(&event, &detection).await.unwrap();
        assert!(matches!(
            action,
            PolicyAction::TimeLock {
                delay_secs: 120,
                ..
            }
        ));
    }

    #[test]
    fn test_approval_flow() {
        let enforcer = PolicyEnforcer::new(test_config());
        let event = test_event("50000");

        let approval_id = enforcer.request_approval(event, "Large transaction".to_string(), 2);

        // First approval
        let complete = enforcer
            .record_approval(&approval_id, "approver1", None, None)
            .unwrap();
        assert!(!complete);

        // Second approval
        let complete = enforcer
            .record_approval(&approval_id, "approver2", None, None)
            .unwrap();
        assert!(complete);

        let pending = enforcer.get_pending_approval(&approval_id).unwrap();
        assert_eq!(pending.status, ApprovalStatus::Approved);
    }
}
