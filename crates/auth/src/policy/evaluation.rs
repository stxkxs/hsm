//! Policy evaluation engine

use super::{
    address::AddressPolicy,
    spending::{SpendingLimit, SpendingPolicy, VelocityLimit},
    tracker::{SpendingTracker, TrackerKey},
    types::{AssetType, TimeWindow},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Policy decision
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    /// Transaction is allowed
    Allow,
    /// Transaction requires approval
    RequireApproval,
    /// Transaction is denied
    Deny,
}

/// Policy violation details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    /// Type of violation
    pub violation_type: ViolationType,
    /// Human-readable message
    pub message: String,
    /// Policy that was violated
    pub policy_name: Option<String>,
    /// Current value
    pub current_value: Option<String>,
    /// Limit value
    pub limit_value: Option<String>,
}

/// Types of policy violations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationType {
    /// Spending limit exceeded
    SpendingLimitExceeded,
    /// Velocity limit exceeded
    VelocityLimitExceeded,
    /// Address not allowed
    AddressNotAllowed,
    /// Address blocklisted
    AddressBlocklisted,
    /// Cooldown period active
    CooldownActive,
    /// Transaction count exceeded
    TransactionCountExceeded,
}

impl PolicyViolation {
    /// Create a spending limit violation
    pub fn spending_limit(current: &str, limit: &str, window: TimeWindow) -> Self {
        Self {
            violation_type: ViolationType::SpendingLimitExceeded,
            message: format!(
                "{} spending limit exceeded: {} / {} max",
                window, current, limit
            ),
            policy_name: None,
            current_value: Some(current.to_string()),
            limit_value: Some(limit.to_string()),
        }
    }

    /// Create a velocity limit violation
    pub fn velocity_limit(count: u32, max: u32, window: TimeWindow) -> Self {
        Self {
            violation_type: ViolationType::VelocityLimitExceeded,
            message: format!(
                "{} transaction limit exceeded: {} / {} max",
                window, count, max
            ),
            policy_name: None,
            current_value: Some(count.to_string()),
            limit_value: Some(max.to_string()),
        }
    }

    /// Create an address not allowed violation
    pub fn address_not_allowed(address: &str) -> Self {
        Self {
            violation_type: ViolationType::AddressNotAllowed,
            message: format!("Address {} not in allowlist", address),
            policy_name: None,
            current_value: Some(address.to_string()),
            limit_value: None,
        }
    }

    /// Create an address blocklisted violation
    pub fn address_blocklisted(address: &str) -> Self {
        Self {
            violation_type: ViolationType::AddressBlocklisted,
            message: format!("Address {} is blocklisted", address),
            policy_name: None,
            current_value: Some(address.to_string()),
            limit_value: None,
        }
    }

    /// Create a cooldown violation
    pub fn cooldown_active(remaining_seconds: u64) -> Self {
        Self {
            violation_type: ViolationType::CooldownActive,
            message: format!("Cooldown active: {} seconds remaining", remaining_seconds),
            policy_name: None,
            current_value: Some(remaining_seconds.to_string()),
            limit_value: None,
        }
    }
}

/// Transaction context for evaluation
#[derive(Debug, Clone)]
pub struct TransactionContext {
    /// Asset type
    pub asset_type: AssetType,
    /// Transaction value
    pub value: String,
    /// Recipient address
    pub recipient: String,
    /// Key ID
    pub key_id: String,
    /// Namespace
    pub namespace: String,
    /// User/client initiating
    pub user: String,
}

/// Evaluation result
#[derive(Debug, Clone)]
pub struct EvaluationResult {
    /// Decision
    pub decision: PolicyDecision,
    /// Violations (if any)
    pub violations: Vec<PolicyViolation>,
    /// Approval tier required (if RequireApproval)
    pub required_approvals: Option<u32>,
}

impl EvaluationResult {
    /// Create an allow result
    pub fn allow() -> Self {
        Self {
            decision: PolicyDecision::Allow,
            violations: Vec::new(),
            required_approvals: None,
        }
    }

    /// Create a deny result
    pub fn deny(violations: Vec<PolicyViolation>) -> Self {
        Self {
            decision: PolicyDecision::Deny,
            violations,
            required_approvals: None,
        }
    }

    /// Create a require approval result
    pub fn require_approval(violations: Vec<PolicyViolation>, required: u32) -> Self {
        Self {
            decision: PolicyDecision::RequireApproval,
            violations,
            required_approvals: Some(required),
        }
    }

    /// Check if allowed
    pub fn is_allowed(&self) -> bool {
        self.decision == PolicyDecision::Allow
    }

    /// Check if denied
    pub fn is_denied(&self) -> bool {
        self.decision == PolicyDecision::Deny
    }

    /// Check if requires approval
    pub fn requires_approval(&self) -> bool {
        self.decision == PolicyDecision::RequireApproval
    }
}

/// Policy evaluator
pub struct PolicyEvaluator {
    /// Spending policy
    spending_policy: Option<SpendingPolicy>,
    /// Address policy
    address_policy: Option<AddressPolicy>,
    /// Spending tracker
    tracker: Arc<SpendingTracker>,
}

impl PolicyEvaluator {
    /// Create a new policy evaluator
    pub fn new(tracker: Arc<SpendingTracker>) -> Self {
        Self {
            spending_policy: None,
            address_policy: None,
            tracker,
        }
    }

    /// Set spending policy
    pub fn with_spending_policy(mut self, policy: SpendingPolicy) -> Self {
        self.spending_policy = Some(policy);
        self
    }

    /// Set address policy
    pub fn with_address_policy(mut self, policy: AddressPolicy) -> Self {
        self.address_policy = Some(policy);
        self
    }

    /// Evaluate a transaction
    pub fn evaluate(&self, ctx: &TransactionContext) -> EvaluationResult {
        let mut violations = Vec::new();
        let mut soft_violations = Vec::new();

        // Check address policy first
        if let Some(ref address_policy) = self.address_policy {
            if !address_policy.is_allowed(&ctx.recipient) {
                let violation = match address_policy.mode {
                    super::address::AddressRestrictionMode::Allowlist => {
                        PolicyViolation::address_not_allowed(&ctx.recipient)
                    }
                    super::address::AddressRestrictionMode::Blocklist => {
                        PolicyViolation::address_blocklisted(&ctx.recipient)
                    }
                };
                return EvaluationResult::deny(vec![violation]);
            }
        }

        // Check spending limits
        if let Some(ref spending_policy) = self.spending_policy {
            // Skip if bypass address
            if !spending_policy.is_bypass_address(&ctx.recipient) {
                // Check spending limits
                for limit in spending_policy.limits_for_asset(&ctx.asset_type) {
                    if let Some(violation) = self.check_spending_limit(ctx, limit) {
                        if limit.hard_limit {
                            violations.push(violation);
                        } else {
                            soft_violations.push(violation);
                        }
                    }
                }

                // Check velocity limits
                for velocity in &spending_policy.velocity_limits {
                    if let Some(ref asset) = velocity.asset_type {
                        if !asset.matches(&ctx.asset_type) {
                            continue;
                        }
                    }

                    if let Some(violation) = self.check_velocity_limit(ctx, velocity) {
                        violations.push(violation);
                    }
                }
            }
        }

        // Return result based on violations
        if !violations.is_empty() {
            EvaluationResult::deny(violations)
        } else if !soft_violations.is_empty() {
            // Soft violations require approval
            EvaluationResult::require_approval(soft_violations, 1)
        } else {
            EvaluationResult::allow()
        }
    }

    /// Check a single spending limit
    fn check_spending_limit(
        &self,
        ctx: &TransactionContext,
        limit: &SpendingLimit,
    ) -> Option<PolicyViolation> {
        // Per-transaction check
        if limit.window == TimeWindow::PerTransaction {
            if limit.exceeds(&ctx.value) {
                return Some(PolicyViolation::spending_limit(
                    &ctx.value,
                    &limit.max_value,
                    TimeWindow::PerTransaction,
                ));
            }
            return None;
        }

        // Aggregate check
        let key = TrackerKey::for_key(&ctx.asset_type, &ctx.key_id);
        let aggregate = self.tracker.get_aggregate(&key, limit.window);

        let current_value = aggregate.total_value;
        let new_value = ctx.value.parse::<u128>().unwrap_or(0);
        let total = current_value.saturating_add(new_value);

        if let Some(max) = limit.max_value_u128() {
            if total > max {
                return Some(PolicyViolation::spending_limit(
                    &total.to_string(),
                    &limit.max_value,
                    limit.window,
                ));
            }
        }

        // Check transaction count
        if let Some(max_tx) = limit.max_transactions {
            if aggregate.tx_count >= max_tx {
                return Some(PolicyViolation::velocity_limit(
                    aggregate.tx_count,
                    max_tx,
                    limit.window,
                ));
            }
        }

        None
    }

    /// Check velocity limit
    fn check_velocity_limit(
        &self,
        ctx: &TransactionContext,
        limit: &VelocityLimit,
    ) -> Option<PolicyViolation> {
        let key = TrackerKey::for_key(&ctx.asset_type, &ctx.key_id);
        let aggregate = self.tracker.get_aggregate(&key, limit.window);

        // Check count
        if limit.exceeds_count(aggregate.tx_count) {
            return Some(PolicyViolation::velocity_limit(
                aggregate.tx_count,
                limit.max_count,
                limit.window,
            ));
        }

        // Check cooldown
        if let Some(cooldown) = limit.cooldown_seconds {
            if let Some(since_last) = self.tracker.time_since_last_tx(&key, limit.window) {
                let cooldown_duration = chrono::Duration::seconds(cooldown as i64);
                if since_last < cooldown_duration {
                    let remaining = (cooldown_duration - since_last).num_seconds() as u64;
                    return Some(PolicyViolation::cooldown_active(remaining));
                }
            }
        }

        // Check total value
        if let Some(ref max_total) = limit.max_total_value {
            let current = aggregate.total_value;
            let new_value = ctx.value.parse::<u128>().unwrap_or(0);
            let total = current.saturating_add(new_value);

            if limit.exceeds_value(&total.to_string()) {
                return Some(PolicyViolation::spending_limit(
                    &total.to_string(),
                    max_total,
                    limit.window,
                ));
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_context(value: &str, recipient: &str) -> TransactionContext {
        TransactionContext {
            asset_type: AssetType::native("ETH"),
            value: value.to_string(),
            recipient: recipient.to_string(),
            key_id: "key-1".to_string(),
            namespace: "default".to_string(),
            user: "alice".to_string(),
        }
    }

    #[test]
    fn test_allow_transaction() {
        let tracker = Arc::new(SpendingTracker::new());
        let evaluator = PolicyEvaluator::new(tracker);

        let ctx = create_context("1000", "0x1234");
        let result = evaluator.evaluate(&ctx);

        assert!(result.is_allowed());
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_spending_limit_deny() {
        let tracker = Arc::new(SpendingTracker::new());
        let spending = SpendingPolicy::new().add_limit(SpendingLimit::new(
            AssetType::native("ETH"),
            TimeWindow::PerTransaction,
            "1000",
        ));

        let evaluator = PolicyEvaluator::new(tracker).with_spending_policy(spending);

        let ctx = create_context("2000", "0x1234");
        let result = evaluator.evaluate(&ctx);

        assert!(result.is_denied());
        assert_eq!(result.violations.len(), 1);
        assert_eq!(
            result.violations[0].violation_type,
            ViolationType::SpendingLimitExceeded
        );
    }

    #[test]
    fn test_address_blocklist() {
        let tracker = Arc::new(SpendingTracker::new());
        let address = AddressPolicy::blocklist().add_addresses(&["0xbad"]);

        let evaluator = PolicyEvaluator::new(tracker).with_address_policy(address);

        // Blocklisted address should be denied
        let ctx = create_context("1000", "0xbad");
        let result = evaluator.evaluate(&ctx);
        assert!(result.is_denied());

        // Other addresses should be allowed
        let ctx = create_context("1000", "0xgood");
        let result = evaluator.evaluate(&ctx);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_soft_limit_requires_approval() {
        let tracker = Arc::new(SpendingTracker::new());
        let spending = SpendingPolicy::new().add_limit(
            SpendingLimit::new(AssetType::native("ETH"), TimeWindow::PerTransaction, "1000")
                .soft_limit(),
        );

        let evaluator = PolicyEvaluator::new(tracker).with_spending_policy(spending);

        let ctx = create_context("2000", "0x1234");
        let result = evaluator.evaluate(&ctx);

        assert!(result.requires_approval());
    }
}
