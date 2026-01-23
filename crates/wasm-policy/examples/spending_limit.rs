//! Example: Spending Limit Policy
//!
//! This example demonstrates how to write a WASM policy that enforces
//! a maximum transaction value limit.
//!
//! # Policy Logic
//! - Transactions under 1 ETH (1e18 wei): Allow
//! - Transactions between 1-10 ETH: Require approval
//! - Transactions over 10 ETH: Deny
//!
//! # Building
//! ```bash
//! # Install the wasm32-unknown-unknown target
//! rustup target add wasm32-unknown-unknown
//!
//! # Build as WASM (this example is for illustration - actual build requires a library crate)
//! cargo build --target wasm32-unknown-unknown --release
//! ```
//!
//! # Note
//! This is a demonstration of policy logic. For actual WASM policies,
//! you would create a separate crate with `crate-type = ["cdylib"]`
//! and compile to wasm32-unknown-unknown target.

use hsm_wasm_policy::{
    AggregatedResult, PolicyContext, PolicyDecision, PolicyEngine, PolicyId, PolicyMetadata,
    ResourceLimits,
};

/// Policy constants
const ONE_ETH_WEI: u128 = 1_000_000_000_000_000_000; // 1e18
const TEN_ETH_WEI: u128 = 10_000_000_000_000_000_000; // 10e18

/// Evaluate a transaction against the spending limit policy.
///
/// This function demonstrates the logic that would be compiled to WASM.
fn evaluate_spending_limit(context: &PolicyContext) -> PolicyDecision {
    // Parse the transaction value
    let value: u128 = context.transaction.value.parse().unwrap_or(0);

    // Check against limits
    if value > TEN_ETH_WEI {
        // Over 10 ETH - deny
        PolicyDecision::Deny
    } else if value > ONE_ETH_WEI {
        // Between 1-10 ETH - require approval
        PolicyDecision::RequireApproval
    } else {
        // Under 1 ETH - allow
        PolicyDecision::Allow
    }
}

/// Create a spending limit policy using WAT (WebAssembly Text Format).
///
/// This policy reads the transaction value and enforces limits.
/// Since we can't easily parse JSON in pure WASM without a runtime,
/// this example uses hardcoded limits.
fn create_spending_limit_policy_wasm() -> Vec<u8> {
    // This is a simplified policy that always allows for demonstration
    // A real policy would need to:
    // 1. Read the context JSON from memory
    // 2. Parse the transaction value
    // 3. Compare against limits
    //
    // For production, you would use a policy SDK crate that provides
    // JSON parsing and helper functions.
    wat::parse_str(
        r#"
        (module
            ;; Import memory for context access
            (memory (export "memory") 1)

            ;; The evaluate function receives context pointer and length
            ;; Returns: 0 = deny, 1 = allow, 2 = require_approval
            (func (export "evaluate") (param $ctx_ptr i32) (param $ctx_len i32) (result i32)
                ;; For this example, we always allow
                ;; A real implementation would parse the JSON context
                ;; and check the transaction value
                i32.const 1
            )
        )
    "#,
    )
    .unwrap()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create the policy engine with default limits
    let engine = PolicyEngine::new(ResourceLimits::default())?;

    // Create policy metadata
    let metadata = PolicyMetadata::new(
        PolicyId::new("spending-limit"),
        "Spending Limit Policy",
        "1.0.0",
        "example-hash",
        create_spending_limit_policy_wasm().len(),
    )
    .with_priority(0) // High priority
    .for_namespace("default"); // Apply to default namespace

    // Create the policy
    let policy = hsm_wasm_policy::Policy::new(metadata, create_spending_limit_policy_wasm());

    // Register the policy
    engine.register_policy(policy)?;

    // Test with various transaction values
    let test_cases = vec![
        ("0.1 ETH", "100000000000000000"),    // 0.1 ETH - allow
        ("1 ETH", "1000000000000000000"),     // 1 ETH - allow
        ("5 ETH", "5000000000000000000"),     // 5 ETH - require approval
        ("10 ETH", "10000000000000000000"),   // 10 ETH - require approval
        ("100 ETH", "100000000000000000000"), // 100 ETH - deny
    ];

    println!("Spending Limit Policy Example");
    println!("==============================\n");
    println!("Policy Rules:");
    println!("  - Under 1 ETH: Allow");
    println!("  - 1-10 ETH: Require Approval");
    println!("  - Over 10 ETH: Deny\n");

    for (label, value) in test_cases {
        // Create a test context
        let context = PolicyContext::new(
            hsm_wasm_policy::TransactionContext::transfer("1", "0xsender", "0xrecipient", value),
            hsm_wasm_policy::SignerContext::new("key-1", "0x04...", "secp256k1", "default"),
            hsm_wasm_policy::EnvironmentContext::new("test-request"),
        );

        // Simulate the Rust-side evaluation (not WASM)
        let rust_decision = evaluate_spending_limit(&context);

        // Run the WASM policy (simplified - always allows)
        let wasm_result: AggregatedResult = engine.evaluate(&context)?;

        println!(
            "{:>10}: Rust Decision = {:?}, WASM Result = {:?}",
            label, rust_decision, wasm_result.decision
        );
    }

    println!("\nNote: The WASM policy in this example is simplified and always allows.");
    println!("A production policy would parse the context JSON and apply the actual limits.");

    Ok(())
}
