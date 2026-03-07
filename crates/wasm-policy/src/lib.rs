#![deny(unsafe_code)]
//! WebAssembly Policy Engine for HSM
//!
//! This module provides a WebAssembly-based policy engine that allows users to write
//! custom transaction authorization policies in any language that compiles to WASM.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    WASM Policy Engine                                │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                       │
//! │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐              │
//! │  │   Policy    │    │   Module    │    │  Execution  │              │
//! │  │   Store     │───▶│   Cache     │───▶│   Engine    │              │
//! │  └─────────────┘    └─────────────┘    └─────────────┘              │
//! │         │                                     │                       │
//! │         │           ┌─────────────┐          │                       │
//! │         └──────────▶│    Host     │◀─────────┘                       │
//! │                     │  Functions  │                                   │
//! │                     └─────────────┘                                   │
//! │                           │                                           │
//! │         ┌─────────────────┼─────────────────┐                        │
//! │         ▼                 ▼                 ▼                        │
//! │  ┌───────────┐     ┌───────────┐     ┌───────────┐                  │
//! │  │   Log     │     │  Context  │     │  Crypto   │                  │
//! │  │  Access   │     │  Access   │     │  Helpers  │                  │
//! │  └───────────┘     └───────────┘     └───────────┘                  │
//! │                                                                       │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Features
//!
//! - **Custom Policies**: Write policies in Rust, AssemblyScript, or any WASM language
//! - **Resource Limits**: Configurable gas, memory, and time limits
//! - **Host Functions**: Access to transaction context, logging, and crypto helpers
//! - **Module Caching**: Compiled modules are cached for performance
//! - **Sandboxed Execution**: Policies run in isolated WASM sandboxes
//!
//! # Policy Interface
//!
//! Policies must export a function with the following signature:
//!
//! ```text
//! // Returns: 0 = deny, 1 = allow, 2 = require_approval
//! fn evaluate(context_ptr: i32, context_len: i32) -> i32
//! ```
//!
//! # Example Policy (Rust)
//!
//! ```rust,ignore
//! use hsm_wasm_policy::PolicyContext;
//!
//! #[no_mangle]
//! pub extern "C" fn evaluate(context_ptr: i32, context_len: i32) -> i32 {
//!     // Read context from memory
//!     let context: PolicyContext = /* deserialize from memory */;
//!
//!     // Check transaction value
//!     if context.transaction.value > 1_000_000 {
//!         return 2; // Require approval
//!     }
//!
//!     // Check recipient
//!     if context.transaction.to.starts_with("0x000") {
//!         return 0; // Deny
//!     }
//!
//!     1 // Allow
//! }
//! ```

pub mod context;
pub mod engine;
pub mod error;
pub mod host;
pub mod limits;
pub mod policy;
pub mod store;

pub use context::{EnvironmentContext, PolicyContext, SignerContext, TransactionContext};
pub use engine::{AggregatedResult, EvaluationResult, PolicyEngine};
pub use error::{PolicyError, Result};
pub use host::{HostFunctions, HostState, LogEntry, LogLevel};
pub use limits::{ExecutionStats, ResourceLimits};
pub use policy::{Policy, PolicyDecision, PolicyId, PolicyMetadata};
pub use store::PolicyStore;

/// Version of the policy ABI.
pub const ABI_VERSION: u32 = 1;

/// Maximum policy size in bytes (1 MB).
pub const MAX_POLICY_SIZE: usize = 1024 * 1024;
