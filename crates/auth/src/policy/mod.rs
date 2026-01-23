//! Transaction Policy Engine
//!
//! Provides comprehensive transaction policy enforcement including:
//! - Spending limits (per-transaction, hourly, daily, weekly, monthly)
//! - Address restrictions (allowlist/blocklist)
//! - Multi-signature approval workflows
//! - Velocity controls
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                      Policy Engine                               │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                   │
//! │  ┌──────────────────┐  ┌──────────────────┐                     │
//! │  │  Spending Limits │  │ Address Policies │                     │
//! │  │  - Per-tx max    │  │  - Allowlist     │                     │
//! │  │  - Hourly/Daily  │  │  - Blocklist     │                     │
//! │  │  - Weekly/Monthly│  │  - Pattern match │                     │
//! │  └──────────────────┘  └──────────────────┘                     │
//! │           │                      │                               │
//! │           └──────────┬───────────┘                               │
//! │                      ▼                                           │
//! │           ┌──────────────────────┐                              │
//! │           │   Policy Evaluator   │                              │
//! │           │  - Sequential eval   │                              │
//! │           │  - First deny wins   │                              │
//! │           └──────────────────────┘                              │
//! │                      │                                           │
//! │                      ▼                                           │
//! │           ┌──────────────────────┐                              │
//! │           │  Approval Manager    │                              │
//! │           │  - Multi-sig require │                              │
//! │           │  - Time delays       │                              │
//! │           │  - Escalation tiers  │                              │
//! │           └──────────────────────┘                              │
//! │                                                                   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

pub mod address;
pub mod approval;
pub mod evaluation;
pub mod spending;
pub mod storage;
pub mod tracker;
pub mod types;

pub use address::{AddressPolicy, AddressRestrictionMode};
pub use approval::{ApprovalManager, ApprovalPolicy, ApprovalRequest, ApprovalStatus};
pub use evaluation::{PolicyDecision, PolicyEvaluator, PolicyViolation};
pub use spending::{SpendingLimit, VelocityLimit};
pub use storage::PolicyStore;
pub use tracker::SpendingTracker;
pub use types::{AssetType, Policy, PolicyId, PolicyScope, TimeWindow};
