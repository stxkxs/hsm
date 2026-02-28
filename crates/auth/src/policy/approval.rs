//! Multi-signature approval workflows

use chrono::{DateTime, Duration, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Approval status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalStatus {
    /// Waiting for approvals
    Pending,
    /// Approved
    Approved,
    /// Rejected
    Rejected,
    /// Expired
    Expired,
    /// Cancelled by requester
    Cancelled,
}

/// Individual approval vote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalVote {
    /// Approver identity
    pub approver: String,
    /// Vote (true = approve, false = reject)
    pub approved: bool,
    /// Vote timestamp
    pub timestamp: DateTime<Utc>,
    /// Optional comment
    pub comment: Option<String>,
}

/// Escalation tier for large transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationTier {
    /// Threshold value that triggers this tier
    pub threshold: String,
    /// Required number of approvals
    pub required_approvals: u32,
    /// List of approvers for this tier
    pub approvers: Vec<String>,
    /// Optional time delay before execution
    pub time_delay_seconds: Option<u64>,
}

impl EscalationTier {
    /// Create a new escalation tier
    pub fn new(threshold: &str, required_approvals: u32, approvers: Vec<String>) -> Self {
        Self {
            threshold: threshold.to_string(),
            required_approvals,
            approvers,
            time_delay_seconds: None,
        }
    }

    /// Add time delay
    pub fn with_delay(mut self, seconds: u64) -> Self {
        self.time_delay_seconds = Some(seconds);
        self
    }

    /// Check if a value triggers this tier
    pub fn triggers(&self, value: &str) -> bool {
        if let (Ok(threshold), Ok(val)) = (self.threshold.parse::<u128>(), value.parse::<u128>()) {
            val >= threshold
        } else {
            false
        }
    }
}

/// Approval policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalPolicy {
    /// Minimum number of approvals required
    pub min_approvals: u32,
    /// List of default approvers
    pub approvers: Vec<String>,
    /// Escalation tiers for large transactions
    pub escalation_tiers: Vec<EscalationTier>,
    /// Default time delay before execution (seconds)
    pub time_delay_seconds: Option<u64>,
    /// Approval request expiration (seconds)
    pub expiration_seconds: u64,
    /// Allow requester to be an approver
    pub requester_can_approve: bool,
}

impl ApprovalPolicy {
    /// Create a new approval policy
    pub fn new(min_approvals: u32, approvers: Vec<String>) -> Self {
        Self {
            min_approvals,
            approvers,
            escalation_tiers: Vec::new(),
            time_delay_seconds: None,
            expiration_seconds: 86400, // 24 hours default
            requester_can_approve: false,
        }
    }

    /// Add an escalation tier
    pub fn add_tier(mut self, tier: EscalationTier) -> Self {
        self.escalation_tiers.push(tier);
        // Sort by threshold descending
        self.escalation_tiers.sort_by(|a, b| {
            let a_val = a.threshold.parse::<u128>().unwrap_or(0);
            let b_val = b.threshold.parse::<u128>().unwrap_or(0);
            b_val.cmp(&a_val)
        });
        self
    }

    /// Set time delay
    pub fn with_delay(mut self, seconds: u64) -> Self {
        self.time_delay_seconds = Some(seconds);
        self
    }

    /// Set expiration
    pub fn with_expiration(mut self, seconds: u64) -> Self {
        self.expiration_seconds = seconds;
        self
    }

    /// Allow requester to approve their own request
    pub fn allow_self_approval(mut self) -> Self {
        self.requester_can_approve = true;
        self
    }

    /// Get the applicable tier for a value
    pub fn get_tier(&self, value: &str) -> Option<&EscalationTier> {
        self.escalation_tiers.iter().find(|t| t.triggers(value))
    }

    /// Get required approvals for a value
    pub fn required_approvals(&self, value: &str) -> u32 {
        self.get_tier(value)
            .map(|t| t.required_approvals)
            .unwrap_or(self.min_approvals)
    }

    /// Get approvers for a value
    pub fn get_approvers(&self, value: &str) -> &[String] {
        self.get_tier(value)
            .map(|t| t.approvers.as_slice())
            .unwrap_or(&self.approvers)
    }

    /// Get time delay for a value
    pub fn get_delay(&self, value: &str) -> Option<u64> {
        self.get_tier(value)
            .and_then(|t| t.time_delay_seconds)
            .or(self.time_delay_seconds)
    }
}

impl Default for ApprovalPolicy {
    fn default() -> Self {
        Self::new(1, vec![])
    }
}

/// Approval request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Unique request ID
    pub id: String,
    /// Requester identity
    pub requester: String,
    /// Transaction details (JSON)
    pub transaction: serde_json::Value,
    /// Transaction value (for tier determination)
    pub value: String,
    /// Key ID
    pub key_id: String,
    /// Namespace
    pub namespace: String,
    /// Status
    pub status: ApprovalStatus,
    /// Votes received
    pub votes: Vec<ApprovalVote>,
    /// Required approvals
    pub required_approvals: u32,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Earliest execution time (if time delay is set)
    pub earliest_execution: Option<DateTime<Utc>>,
}

impl ApprovalRequest {
    /// Create a new approval request
    pub fn new(
        requester: &str,
        transaction: serde_json::Value,
        value: &str,
        key_id: &str,
        namespace: &str,
        policy: &ApprovalPolicy,
    ) -> Self {
        let now = Utc::now();
        let required = policy.required_approvals(value);
        let delay = policy.get_delay(value);

        Self {
            id: Uuid::new_v4().to_string(),
            requester: requester.to_string(),
            transaction,
            value: value.to_string(),
            key_id: key_id.to_string(),
            namespace: namespace.to_string(),
            status: ApprovalStatus::Pending,
            votes: Vec::new(),
            required_approvals: required,
            created_at: now,
            expires_at: now + Duration::seconds(policy.expiration_seconds as i64),
            earliest_execution: delay.map(|d| now + Duration::seconds(d as i64)),
        }
    }

    /// Add a vote
    pub fn add_vote(&mut self, approver: &str, approved: bool, comment: Option<String>) -> bool {
        // Check if already voted
        if self.votes.iter().any(|v| v.approver == approver) {
            return false;
        }

        self.votes.push(ApprovalVote {
            approver: approver.to_string(),
            approved,
            timestamp: Utc::now(),
            comment,
        });

        self.update_status();
        true
    }

    /// Update status based on votes
    fn update_status(&mut self) {
        if self.status != ApprovalStatus::Pending {
            return;
        }

        // Check expiration
        if Utc::now() > self.expires_at {
            self.status = ApprovalStatus::Expired;
            return;
        }

        // Count approvals and rejections
        let approvals = self.votes.iter().filter(|v| v.approved).count() as u32;
        let rejections = self.votes.iter().filter(|v| !v.approved).count();

        // Any rejection = rejected
        if rejections > 0 {
            self.status = ApprovalStatus::Rejected;
            return;
        }

        // Enough approvals = approved
        if approvals >= self.required_approvals {
            self.status = ApprovalStatus::Approved;
        }
    }

    /// Check if the request can be executed
    pub fn can_execute(&self) -> bool {
        if self.status != ApprovalStatus::Approved {
            return false;
        }

        // Check time delay
        if let Some(earliest) = self.earliest_execution {
            if Utc::now() < earliest {
                return false;
            }
        }

        true
    }

    /// Get time remaining until execution is allowed
    pub fn time_until_execution(&self) -> Option<Duration> {
        if self.status != ApprovalStatus::Approved {
            return None;
        }

        self.earliest_execution.map(|earliest| {
            let now = Utc::now();
            if earliest > now {
                earliest - now
            } else {
                Duration::zero()
            }
        })
    }

    /// Cancel the request
    pub fn cancel(&mut self) -> bool {
        if self.status == ApprovalStatus::Pending {
            self.status = ApprovalStatus::Cancelled;
            true
        } else {
            false
        }
    }
}

/// Approval manager
pub struct ApprovalManager {
    /// Pending requests
    requests: Arc<DashMap<String, ApprovalRequest>>,
    /// Default policy
    default_policy: ApprovalPolicy,
}

impl ApprovalManager {
    /// Create a new approval manager
    pub fn new(default_policy: ApprovalPolicy) -> Self {
        Self {
            requests: Arc::new(DashMap::new()),
            default_policy,
        }
    }

    /// Create a new approval request
    pub fn create_request(
        &self,
        requester: &str,
        transaction: serde_json::Value,
        value: &str,
        key_id: &str,
        namespace: &str,
    ) -> ApprovalRequest {
        let request = ApprovalRequest::new(
            requester,
            transaction,
            value,
            key_id,
            namespace,
            &self.default_policy,
        );
        self.requests.insert(request.id.clone(), request.clone());
        request
    }

    /// Get a request by ID
    pub fn get_request(&self, id: &str) -> Option<ApprovalRequest> {
        self.requests.get(id).map(|r| r.clone())
    }

    /// Add a vote to a request
    pub fn vote(
        &self,
        request_id: &str,
        approver: &str,
        approved: bool,
        comment: Option<String>,
    ) -> Result<ApprovalRequest, String> {
        let mut request = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| "Request not found".to_string())?;

        // Check if approver is authorized
        let approvers = self.default_policy.get_approvers(&request.value);
        if !approvers.contains(&approver.to_string()) {
            return Err("Not an authorized approver".to_string());
        }

        // Check self-approval
        if request.requester == approver && !self.default_policy.requester_can_approve {
            return Err("Requester cannot approve their own request".to_string());
        }

        if !request.add_vote(approver, approved, comment) {
            return Err("Already voted".to_string());
        }

        Ok(request.clone())
    }

    /// Get pending requests for an approver
    pub fn pending_for_approver(&self, approver: &str) -> Vec<ApprovalRequest> {
        self.requests
            .iter()
            .filter(|r| {
                r.status == ApprovalStatus::Pending
                    && self
                        .default_policy
                        .get_approvers(&r.value)
                        .contains(&approver.to_string())
                    && !r.votes.iter().any(|v| v.approver == approver)
            })
            .map(|r| r.clone())
            .collect()
    }

    /// Cleanup expired requests
    pub fn cleanup_expired(&self) -> usize {
        let mut count = 0;
        self.requests.retain(|_, request| {
            if request.status == ApprovalStatus::Pending && Utc::now() > request.expires_at {
                count += 1;
                false
            } else {
                true
            }
        });
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_approval_policy() {
        let policy = ApprovalPolicy::new(2, vec!["alice".into(), "bob".into()]).add_tier(
            EscalationTier::new(
                "1000000",
                3,
                vec!["alice".into(), "bob".into(), "charlie".into()],
            )
            .with_delay(3600),
        );

        assert_eq!(policy.required_approvals("500000"), 2);
        assert_eq!(policy.required_approvals("2000000"), 3);
        assert_eq!(policy.get_delay("500000"), None);
        assert_eq!(policy.get_delay("2000000"), Some(3600));
    }

    #[test]
    fn test_approval_request() {
        let policy = ApprovalPolicy::new(2, vec!["alice".into(), "bob".into()]);
        let mut request = ApprovalRequest::new(
            "requester",
            json!({"to": "0x1234"}),
            "1000",
            "key-1",
            "default",
            &policy,
        );

        assert_eq!(request.status, ApprovalStatus::Pending);
        assert_eq!(request.required_approvals, 2);

        // First approval
        assert!(request.add_vote("alice", true, None));
        assert_eq!(request.status, ApprovalStatus::Pending);

        // Second approval
        assert!(request.add_vote("bob", true, None));
        assert_eq!(request.status, ApprovalStatus::Approved);
    }

    #[test]
    fn test_rejection() {
        let policy = ApprovalPolicy::new(2, vec!["alice".into(), "bob".into()]);
        let mut request =
            ApprovalRequest::new("requester", json!({}), "1000", "key-1", "default", &policy);

        // One rejection = rejected
        request.add_vote("alice", false, Some("Suspicious transaction".into()));
        assert_eq!(request.status, ApprovalStatus::Rejected);
    }

    #[test]
    fn test_duplicate_vote() {
        let policy = ApprovalPolicy::new(2, vec!["alice".into()]);
        let mut request =
            ApprovalRequest::new("requester", json!({}), "1000", "key-1", "default", &policy);

        assert!(request.add_vote("alice", true, None));
        assert!(!request.add_vote("alice", true, None)); // Duplicate
    }

    #[test]
    fn test_approval_manager() {
        let policy = ApprovalPolicy::new(1, vec!["alice".into()]);
        let manager = ApprovalManager::new(policy);

        let request =
            manager.create_request("bob", json!({"amount": 1000}), "1000", "key-1", "default");

        let updated = manager.vote(&request.id, "alice", true, None).unwrap();
        assert_eq!(updated.status, ApprovalStatus::Approved);
    }
}
