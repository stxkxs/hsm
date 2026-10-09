#![deny(unsafe_code)]
//! Formal verification framework for HSM cryptographic operations.
//!
//! This crate provides formal verification using SMT solvers (Z3) and bounded
//! model checking to prove correctness of cryptographic primitives.
//!
//! # Verification Modules
//!
//! - **SMT Encoding**: Encode finite-field operations as SMT constraints
//! - **Bounded Verification**: Verify crypto operations within bounded field sizes
//! - **Ed25519 Verification**: Formally verify Ed25519 signature operations
//! - **ECDSA Verification**: Verify ECDSA nonce generation and signature correctness
//! - **RSA Verification**: Verify RSA padding schemes (PKCS#1 v1.5, PSS)
//! - **Shamir Verification**: Prove Shamir's Secret Sharing correctness
//!
//! # Research Foundation
//!
//! Based on:
//! - "Bounded Verification for Finite-Field-Blasting" (Ozdemir, Wahby, Brown, 2023/2025)
//! - "CirC: Compiler Infrastructure for Proof Systems" (Ozdemir, Brown, Wahby, 2020)
//! - cvc5 and Z3 SMT solvers
//!
//! # Examples
//!
//! ```rust
//! use hsm_verification::ed25519::verify_ed25519_correctness;
//!
//! // Verify Ed25519 signature scheme properties
//! let result = verify_ed25519_correctness();
//! assert!(result.is_ok());
//! ```

pub mod bounded_check;
pub mod ecdsa;
pub mod ed25519;
pub mod error;
pub mod rsa;
pub mod shamir;
pub mod smt_encoder;

pub use error::{Result, VerificationError};

use z3::Config;

/// Solver configuration applied to a scoped Z3 context.
///
/// Z3 terms and solvers are built in the calling thread's implicit context.
/// [`VerificationContext::run`] swaps in a context built from this
/// configuration for the duration of a closure.
pub struct VerificationContext {
    config: Config,
}

impl VerificationContext {
    /// Create a new verification context
    pub fn new() -> Self {
        let mut cfg = Config::new();
        cfg.set_timeout_msec(60000); // 60 second timeout
        cfg.set_model_generation(true);
        Self { config: cfg }
    }

    /// Run `f` with every Z3 call inside it bound to a fresh context built
    /// from this configuration.
    ///
    /// Z3 objects created inside `f` belong to that context and cannot be
    /// returned from it, which the `Send + Sync` bounds enforce.
    pub fn run<R: Send + Sync>(&self, f: impl FnOnce() -> R + Send + Sync) -> R {
        z3::with_z3_config(&self.config, f)
    }

    /// Set solver timeout in milliseconds
    pub fn set_timeout(&mut self, timeout_ms: u64) {
        self.config.set_timeout_msec(timeout_ms);
    }
}

impl Default for VerificationContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_context_creation() {
        let ctx = VerificationContext::new();
        // An empty assertion set is satisfiable in the configured context.
        // Full Z3 integration tests are in the integration test suite
        let result = ctx.run(|| z3::Solver::new().check());
        assert_eq!(result, z3::SatResult::Sat);
    }
}
