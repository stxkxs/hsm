//! Integration tests for the HSM WASM Policy Engine crate.
//!
//! Covers: policy engine initialization, policy store operations (add/remove/list),
//! limit configuration, and context creation and population.

use hsm_wasm_policy::{
    EnvironmentContext, ExecutionStats, HostFunctions, HostState, LogLevel, Policy, PolicyContext,
    PolicyDecision, PolicyEngine, PolicyId, PolicyMetadata, PolicyStore, ResourceLimits,
    SignerContext, TransactionContext,
};
use std::sync::Arc;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Minimal WASM module that always returns Allow (1).
fn allow_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (func (export "evaluate") (param i32 i32) (result i32)
                i32.const 1
            )
            (memory (export "memory") 1)
        )
    "#,
    )
    .unwrap()
}

/// Minimal WASM module that always returns Deny (0).
fn deny_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (func (export "evaluate") (param i32 i32) (result i32)
                i32.const 0
            )
            (memory (export "memory") 1)
        )
    "#,
    )
    .unwrap()
}

/// Minimal WASM module that always returns RequireApproval (2).
fn approval_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (func (export "evaluate") (param i32 i32) (result i32)
                i32.const 2
            )
            (memory (export "memory") 1)
        )
    "#,
    )
    .unwrap()
}

/// WASM module that returns an invalid decision value (99).
fn invalid_decision_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (func (export "evaluate") (param i32 i32) (result i32)
                i32.const 99
            )
            (memory (export "memory") 1)
        )
    "#,
    )
    .unwrap()
}

/// WASM module with no evaluate export (invalid).
fn no_evaluate_wasm() -> Vec<u8> {
    wat::parse_str(
        r#"
        (module
            (func (export "other_func") (param i32 i32) (result i32)
                i32.const 1
            )
            (memory (export "memory") 1)
        )
    "#,
    )
    .unwrap()
}

/// Create a wasmtime engine with fuel enabled.
fn test_engine() -> wasmtime::Engine {
    let mut config = wasmtime::Config::new();
    config.consume_fuel(true);
    wasmtime::Engine::new(&config).unwrap()
}

/// Create a basic test context.
fn test_context() -> PolicyContext {
    PolicyContext::new(
        TransactionContext::transfer("1", "0xsender", "0xrecipient", "1000000000000000000"),
        SignerContext::new("key-1", "0x04abcdef", "secp256k1", "default"),
        EnvironmentContext::new("req-integration-test"),
    )
}

fn make_metadata(id: &str, name: &str) -> PolicyMetadata {
    PolicyMetadata::new(PolicyId::new(id), name, "1.0.0", "hash-placeholder", 100)
}

// ---------------------------------------------------------------------------
// 1. Policy Engine Initialization
// ---------------------------------------------------------------------------

#[test]
fn test_engine_creation_default_limits() {
    let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();
    assert!(engine.store().list().is_empty());
}

#[test]
fn test_engine_creation_strict_limits() {
    let engine = PolicyEngine::new(ResourceLimits::strict()).unwrap();
    assert!(engine.store().list().is_empty());
}

#[test]
fn test_engine_creation_relaxed_limits() {
    let engine = PolicyEngine::new(ResourceLimits::relaxed()).unwrap();
    assert!(engine.store().list().is_empty());
}

#[test]
fn test_engine_creation_custom_limits() {
    let limits = ResourceLimits::default()
        .with_execution_time(Duration::from_millis(200))
        .with_memory(32 * 1024 * 1024)
        .with_fuel(50_000_000);

    let engine = PolicyEngine::new(limits).unwrap();
    assert!(engine.store().list().is_empty());
}

#[test]
fn test_engine_with_custom_store() {
    let wasm_engine = test_engine();
    let store = Arc::new(PolicyStore::new(wasm_engine).unwrap());

    let engine = PolicyEngine::with_store(store.clone(), ResourceLimits::default()).unwrap();
    assert!(engine.store().list().is_empty());
}

#[test]
fn test_engine_evaluate_allow_policy() {
    let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();

    let metadata = make_metadata("allow-policy", "Allow Policy");
    engine
        .register_policy(Policy::new(metadata, allow_wasm()))
        .unwrap();

    let result = engine.evaluate(&test_context()).unwrap();
    assert!(result.is_allowed());
    assert!(!result.is_denied());
    assert!(!result.requires_approval());
    assert_eq!(result.results.len(), 1);
}

#[test]
fn test_engine_evaluate_deny_policy() {
    let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();

    let metadata = make_metadata("deny-policy", "Deny Policy");
    engine
        .register_policy(Policy::new(metadata, deny_wasm()))
        .unwrap();

    let result = engine.evaluate(&test_context()).unwrap();
    assert!(result.is_denied());
    assert!(!result.is_allowed());
    assert_eq!(result.denying_policy().unwrap().as_str(), "deny-policy");
}

#[test]
fn test_engine_evaluate_approval_policy() {
    let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();

    let metadata = make_metadata("approval-policy", "Approval Policy");
    engine
        .register_policy(Policy::new(metadata, approval_wasm()))
        .unwrap();

    let result = engine.evaluate(&test_context()).unwrap();
    assert!(result.requires_approval());
    assert!(!result.is_allowed());
    assert!(!result.is_denied());
}

#[test]
fn test_engine_evaluate_no_policies_defaults_to_allow() {
    let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();

    let result = engine.evaluate(&test_context()).unwrap();
    assert!(result.is_allowed());
    assert!(result.results.is_empty());
    assert_eq!(result.total_time_ms, 0);
}

#[test]
fn test_engine_deny_overrides_allow() {
    let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();

    // Allow with lower priority (evaluated second)
    let meta_allow = make_metadata("allow-it", "Allow").with_priority(10);
    engine
        .register_policy(Policy::new(meta_allow, allow_wasm()))
        .unwrap();

    // Deny with higher priority (lower number = evaluated first)
    let meta_deny = make_metadata("deny-it", "Deny").with_priority(0);
    engine
        .register_policy(Policy::new(meta_deny, deny_wasm()))
        .unwrap();

    let result = engine.evaluate(&test_context()).unwrap();
    assert!(result.is_denied());
    assert_eq!(result.denying_policy().unwrap().as_str(), "deny-it");
}

#[test]
fn test_engine_evaluate_single_policy() {
    let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();

    let metadata = make_metadata("single-allow", "Single Allow");
    engine
        .register_policy(Policy::new(metadata, allow_wasm()))
        .unwrap();

    let result = engine
        .evaluate_policy(&PolicyId::new("single-allow"), &test_context())
        .unwrap();

    assert_eq!(result.decision, PolicyDecision::Allow);
    assert!(result.error.is_none());
    assert!(result.stats.fuel_consumed > 0);
}

#[test]
fn test_engine_evaluate_nonexistent_policy() {
    let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();

    let result = engine.evaluate_policy(&PolicyId::new("no-such-policy"), &test_context());
    assert!(result.is_err());
}

#[test]
fn test_engine_evaluate_disabled_policy() {
    let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();

    let metadata = make_metadata("disabled-policy", "Disabled").disabled();
    engine
        .register_policy(Policy::new(metadata, allow_wasm()))
        .unwrap();

    // Direct evaluation of disabled policy should fail
    let result = engine.evaluate_policy(&PolicyId::new("disabled-policy"), &test_context());
    assert!(result.is_err());

    // Aggregate evaluation should skip disabled policies
    let agg = engine.evaluate(&test_context()).unwrap();
    assert!(agg.is_allowed());
    assert!(agg.results.is_empty());
}

#[test]
fn test_engine_evaluate_invalid_decision() {
    let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();

    let metadata = make_metadata("invalid-decision", "Invalid Decision");
    engine
        .register_policy(Policy::new(metadata, invalid_decision_wasm()))
        .unwrap();

    // Should result in a deny (error treated as deny for safety)
    let result = engine.evaluate(&test_context()).unwrap();
    assert!(result.is_denied());
}

#[test]
fn test_engine_simulation() {
    let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();

    let metadata = make_metadata("sim-policy", "Simulation Policy");
    engine
        .register_policy(Policy::new(metadata, allow_wasm()))
        .unwrap();

    let result = engine.simulate(&test_context()).unwrap();
    assert!(result.is_allowed());
}

// ---------------------------------------------------------------------------
// 2. Policy Store Operations (Add/Remove/List)
// ---------------------------------------------------------------------------

#[test]
fn test_store_register_and_get() {
    let store = PolicyStore::new(test_engine()).unwrap();

    let metadata = make_metadata("store-test-1", "Store Test 1");
    let policy = Policy::new(metadata, allow_wasm());
    store.register(policy).unwrap();

    let retrieved = store.get(&PolicyId::new("store-test-1"));
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().metadata.name, "Store Test 1");
}

#[test]
fn test_store_register_multiple() {
    let store = PolicyStore::new(test_engine()).unwrap();

    for i in 0..5 {
        let metadata = make_metadata(&format!("policy-{}", i), &format!("Policy {}", i));
        store.register(Policy::new(metadata, allow_wasm())).unwrap();
    }

    assert_eq!(store.list().len(), 5);
}

#[test]
fn test_store_list_returns_all_ids() {
    let store = PolicyStore::new(test_engine()).unwrap();

    let ids = vec!["alpha", "beta", "gamma"];
    for id in &ids {
        let metadata = make_metadata(id, id);
        store.register(Policy::new(metadata, allow_wasm())).unwrap();
    }

    let listed: Vec<String> = store
        .list()
        .iter()
        .map(|p| p.as_str().to_string())
        .collect();
    for id in &ids {
        assert!(listed.contains(&id.to_string()), "Missing policy: {}", id);
    }
}

#[test]
fn test_store_list_metadata() {
    let store = PolicyStore::new(test_engine()).unwrap();

    let meta1 = make_metadata("m1", "Metadata One").with_author("alice");
    let meta2 = make_metadata("m2", "Metadata Two").with_author("bob");

    store.register(Policy::new(meta1, allow_wasm())).unwrap();
    store.register(Policy::new(meta2, allow_wasm())).unwrap();

    let metadata_list = store.list_metadata();
    assert_eq!(metadata_list.len(), 2);

    let names: Vec<String> = metadata_list.iter().map(|m| m.name.clone()).collect();
    assert!(names.contains(&"Metadata One".to_string()));
    assert!(names.contains(&"Metadata Two".to_string()));
}

#[test]
fn test_store_remove() {
    let store = PolicyStore::new(test_engine()).unwrap();

    let metadata = make_metadata("to-remove", "Removable");
    store.register(Policy::new(metadata, allow_wasm())).unwrap();
    assert_eq!(store.list().len(), 1);

    store.remove(&PolicyId::new("to-remove")).unwrap();
    assert_eq!(store.list().len(), 0);
    assert!(store.get(&PolicyId::new("to-remove")).is_none());
}

#[test]
fn test_store_remove_nonexistent() {
    let store = PolicyStore::new(test_engine()).unwrap();
    let result = store.remove(&PolicyId::new("nonexistent"));
    assert!(result.is_err());
}

#[test]
fn test_store_update() {
    let store = PolicyStore::new(test_engine()).unwrap();

    let metadata = make_metadata("updatable", "Version 1");
    store.register(Policy::new(metadata, allow_wasm())).unwrap();

    // Update with new bytecode
    let updated_metadata = make_metadata("updatable", "Version 2");
    store
        .update(Policy::new(updated_metadata, deny_wasm()))
        .unwrap();

    let policy = store.get(&PolicyId::new("updatable")).unwrap();
    assert_eq!(policy.metadata.name, "Version 2");
}

#[test]
fn test_store_update_nonexistent() {
    let store = PolicyStore::new(test_engine()).unwrap();

    let metadata = make_metadata("ghost", "Ghost");
    let result = store.update(Policy::new(metadata, allow_wasm()));
    assert!(result.is_err());
}

#[test]
fn test_store_enable_disable() {
    let store = PolicyStore::new(test_engine()).unwrap();
    let id = PolicyId::new("toggle");

    let metadata = make_metadata("toggle", "Toggle Policy");
    store.register(Policy::new(metadata, allow_wasm())).unwrap();

    // Initially enabled
    assert!(store.get(&id).unwrap().metadata.enabled);

    // Disable
    store.disable(&id).unwrap();
    assert!(!store.get(&id).unwrap().metadata.enabled);

    // Enable
    store.enable(&id).unwrap();
    assert!(store.get(&id).unwrap().metadata.enabled);
}

#[test]
fn test_store_enable_disable_nonexistent() {
    let store = PolicyStore::new(test_engine()).unwrap();
    let id = PolicyId::new("nope");

    assert!(store.enable(&id).is_err());
    assert!(store.disable(&id).is_err());
}

#[test]
fn test_store_get_module() {
    let store = PolicyStore::new(test_engine()).unwrap();

    let metadata = make_metadata("module-test", "Module Test");
    store.register(Policy::new(metadata, allow_wasm())).unwrap();

    let module = store.get_module(&PolicyId::new("module-test")).unwrap();
    // Verify the module has the evaluate export
    assert!(module.exports().any(|e| e.name() == "evaluate"));
}

#[test]
fn test_store_get_module_nonexistent() {
    let store = PolicyStore::new(test_engine()).unwrap();
    let result = store.get_module(&PolicyId::new("no-module"));
    assert!(result.is_err());
}

#[test]
fn test_store_rejects_invalid_bytecode() {
    let store = PolicyStore::new(test_engine()).unwrap();

    let metadata = make_metadata("bad-wasm", "Bad WASM");
    let result = store.register(Policy::new(metadata, vec![0x00, 0x01, 0x02]));
    assert!(result.is_err());
}

#[test]
fn test_store_rejects_missing_evaluate_export() {
    let store = PolicyStore::new(test_engine()).unwrap();

    let metadata = make_metadata("no-eval", "No Evaluate");
    let result = store.register(Policy::new(metadata, no_evaluate_wasm()));
    assert!(result.is_err());
}

#[test]
fn test_store_find_applicable() {
    let store = PolicyStore::new(test_engine()).unwrap();

    // Policy for production namespace only
    let meta1 = make_metadata("prod-policy", "Prod Policy").for_namespace("production");
    store.register(Policy::new(meta1, allow_wasm())).unwrap();

    // Policy for all namespaces
    let meta2 = make_metadata("global-policy", "Global Policy");
    store.register(Policy::new(meta2, allow_wasm())).unwrap();

    // Policy for chain 1 only
    let meta3 = make_metadata("chain1-policy", "Chain 1 Policy").for_chain("1");
    store.register(Policy::new(meta3, allow_wasm())).unwrap();

    // Production, chain 1 -> all three
    let applicable = store.find_applicable("production", "key-1", "1", "transfer");
    assert_eq!(applicable.len(), 3);

    // Staging, chain 1 -> global + chain1
    let applicable = store.find_applicable("staging", "key-1", "1", "transfer");
    assert_eq!(applicable.len(), 2);

    // Staging, chain 137 -> global only
    let applicable = store.find_applicable("staging", "key-1", "137", "transfer");
    assert_eq!(applicable.len(), 1);
    assert_eq!(applicable[0].metadata.id.as_str(), "global-policy");
}

#[test]
fn test_store_find_applicable_respects_disabled() {
    let store = PolicyStore::new(test_engine()).unwrap();

    let metadata = make_metadata("disabled-find", "Disabled");
    store.register(Policy::new(metadata, allow_wasm())).unwrap();

    store.disable(&PolicyId::new("disabled-find")).unwrap();

    let applicable = store.find_applicable("default", "key-1", "1", "transfer");
    assert!(applicable.is_empty());
}

#[test]
fn test_store_find_applicable_sorted_by_priority() {
    let store = PolicyStore::new(test_engine()).unwrap();

    let meta_low = make_metadata("low-prio", "Low Priority").with_priority(100);
    let meta_high = make_metadata("high-prio", "High Priority").with_priority(1);
    let meta_med = make_metadata("med-prio", "Medium Priority").with_priority(50);

    store.register(Policy::new(meta_low, allow_wasm())).unwrap();
    store
        .register(Policy::new(meta_high, allow_wasm()))
        .unwrap();
    store.register(Policy::new(meta_med, allow_wasm())).unwrap();

    let applicable = store.find_applicable("default", "key-1", "1", "transfer");
    assert_eq!(applicable.len(), 3);
    assert_eq!(applicable[0].metadata.id.as_str(), "high-prio");
    assert_eq!(applicable[1].metadata.id.as_str(), "med-prio");
    assert_eq!(applicable[2].metadata.id.as_str(), "low-prio");
}

#[test]
fn test_store_cache_stats() {
    let store = PolicyStore::new(test_engine()).unwrap();

    // Initially empty
    let stats = store.cache_stats();
    assert_eq!(stats.size, 0);
    assert_eq!(stats.capacity, 100);

    // Register a policy (compiles and caches)
    let metadata = make_metadata("cached", "Cached");
    store.register(Policy::new(metadata, allow_wasm())).unwrap();

    let stats = store.cache_stats();
    assert_eq!(stats.size, 1);
}

#[test]
fn test_store_clear_cache() {
    let store = PolicyStore::new(test_engine()).unwrap();

    let metadata = make_metadata("cache-clear", "Cache Clear");
    store.register(Policy::new(metadata, allow_wasm())).unwrap();

    assert_eq!(store.cache_stats().size, 1);

    store.clear_cache();
    assert_eq!(store.cache_stats().size, 0);

    // Module should still be retrievable (recompiled on demand)
    let module = store.get_module(&PolicyId::new("cache-clear")).unwrap();
    assert!(module.exports().any(|e| e.name() == "evaluate"));
    assert_eq!(store.cache_stats().size, 1);
}

#[test]
fn test_store_custom_cache_size() {
    let store = PolicyStore::with_cache_size(test_engine(), 5).unwrap();
    let stats = store.cache_stats();
    assert_eq!(stats.capacity, 5);
}

#[test]
fn test_store_persistent_storage() {
    let dir = tempfile::tempdir().unwrap();

    // Create store with persistence and register a policy
    {
        let store = PolicyStore::with_storage(test_engine(), dir.path()).unwrap();
        let metadata = make_metadata("persist-test", "Persistent");
        store.register(Policy::new(metadata, allow_wasm())).unwrap();
        assert_eq!(store.list().len(), 1);
    }

    // Create a new store from the same path and verify it loads
    {
        let store = PolicyStore::with_storage(test_engine(), dir.path()).unwrap();
        assert_eq!(store.list().len(), 1);
        let policy = store.get(&PolicyId::new("persist-test")).unwrap();
        assert_eq!(policy.metadata.name, "Persistent");
    }
}

// ---------------------------------------------------------------------------
// 3. Limit Configuration
// ---------------------------------------------------------------------------

#[test]
fn test_default_limits_values() {
    let limits = ResourceLimits::default();

    assert_eq!(limits.max_execution_time, Duration::from_millis(100));
    assert_eq!(limits.max_memory_bytes, 16 * 1024 * 1024);
    assert_eq!(limits.max_fuel, 10_000_000);
    assert_eq!(limits.max_stack_size, 1024 * 1024);
    assert_eq!(limits.max_tables, 10);
    assert_eq!(limits.max_table_elements, 10_000);
    assert_eq!(limits.max_memories, 1);
    assert_eq!(limits.max_instances, 10);
}

#[test]
fn test_strict_limits_more_restrictive() {
    let strict = ResourceLimits::strict();
    let default = ResourceLimits::default();

    assert!(strict.max_execution_time < default.max_execution_time);
    assert!(strict.max_memory_bytes < default.max_memory_bytes);
    assert!(strict.max_fuel < default.max_fuel);
    assert!(strict.max_stack_size < default.max_stack_size);
}

#[test]
fn test_relaxed_limits_less_restrictive() {
    let relaxed = ResourceLimits::relaxed();
    let default = ResourceLimits::default();

    assert!(relaxed.max_execution_time > default.max_execution_time);
    assert!(relaxed.max_memory_bytes > default.max_memory_bytes);
    assert!(relaxed.max_fuel > default.max_fuel);
    assert!(relaxed.max_stack_size > default.max_stack_size);
}

#[test]
fn test_limits_builder_chain() {
    let limits = ResourceLimits::new()
        .with_execution_time(Duration::from_millis(500))
        .with_memory(8 * 1024 * 1024)
        .with_fuel(5_000_000);

    assert_eq!(limits.max_execution_time, Duration::from_millis(500));
    assert_eq!(limits.max_memory_bytes, 8 * 1024 * 1024);
    assert_eq!(limits.max_fuel, 5_000_000);
}

#[test]
fn test_execution_stats_default() {
    let stats = ExecutionStats::default();

    assert_eq!(stats.fuel_consumed, 0);
    assert_eq!(stats.peak_memory_bytes, 0);
    assert_eq!(stats.execution_time, Duration::ZERO);
    assert_eq!(stats.host_calls, 0);
}

#[test]
fn test_execution_stats_builders() {
    let stats = ExecutionStats::new()
        .with_fuel(5000)
        .with_time(Duration::from_millis(42));

    assert_eq!(stats.fuel_consumed, 5000);
    assert_eq!(stats.execution_time, Duration::from_millis(42));
}

#[test]
fn test_execution_stats_check_limits_within() {
    let limits = ResourceLimits::default();
    let stats = ExecutionStats::new()
        .with_fuel(100)
        .with_time(Duration::from_millis(1));

    assert!(stats.check_limits(&limits).is_none());
}

#[test]
fn test_execution_stats_check_limits_fuel_exceeded() {
    let limits = ResourceLimits::new().with_fuel(1000);
    let stats = ExecutionStats::new().with_fuel(2000);

    let violation = stats.check_limits(&limits);
    assert!(violation.is_some());

    let msg = violation.unwrap().to_string();
    assert!(msg.contains("Fuel"));
    assert!(msg.contains("2000"));
    assert!(msg.contains("1000"));
}

#[test]
fn test_execution_stats_check_limits_memory_exceeded() {
    let limits = ResourceLimits::new().with_memory(1024);
    let mut stats = ExecutionStats::new();
    stats.peak_memory_bytes = 2048;

    let violation = stats.check_limits(&limits);
    assert!(violation.is_some());

    let msg = violation.unwrap().to_string();
    assert!(msg.contains("Memory"));
}

#[test]
fn test_execution_stats_check_limits_time_exceeded() {
    let limits = ResourceLimits::new().with_execution_time(Duration::from_millis(10));
    let stats = ExecutionStats::new().with_time(Duration::from_millis(50));

    let violation = stats.check_limits(&limits);
    assert!(violation.is_some());

    let msg = violation.unwrap().to_string();
    assert!(msg.contains("Time"));
}

#[test]
fn test_per_policy_resource_limits() {
    let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();

    // Policy with custom strict limits
    let metadata =
        make_metadata("custom-limits", "Custom Limits").with_limits(ResourceLimits::strict());
    engine
        .register_policy(Policy::new(metadata, allow_wasm()))
        .unwrap();

    // Should still evaluate fine (our simple policy is very cheap)
    let result = engine.evaluate(&test_context()).unwrap();
    assert!(result.is_allowed());
}

// ---------------------------------------------------------------------------
// 4. Context Creation and Population
// ---------------------------------------------------------------------------

#[test]
fn test_policy_context_new() {
    let tx = TransactionContext::transfer("1", "0xfrom", "0xto", "1000");
    let signer = SignerContext::new("key-1", "0xpub", "secp256k1", "default");
    let env = EnvironmentContext::new("req-1");

    let context = PolicyContext::new(tx, signer, env);

    assert_eq!(context.transaction.chain_id, "1");
    assert_eq!(context.transaction.from, "0xfrom");
    assert_eq!(context.transaction.to, Some("0xto".to_string()));
    assert_eq!(context.transaction.value, "1000");
    assert_eq!(context.signer.key_id, "key-1");
    assert_eq!(context.signer.namespace, "default");
    assert_eq!(context.environment.request_id, "req-1");
    assert!(!context.environment.is_simulation);
    assert!(context.metadata.is_empty());
}

#[test]
fn test_context_with_metadata() {
    let context = PolicyContext::new(
        TransactionContext::transfer("1", "0xfrom", "0xto", "100"),
        SignerContext::new("key-1", "0xpub", "secp256k1", "default"),
        EnvironmentContext::new("req-1"),
    )
    .with_metadata("department", "engineering")
    .with_metadata("project", "defi");

    assert_eq!(
        context.metadata.get("department"),
        Some(&"engineering".to_string())
    );
    assert_eq!(context.metadata.get("project"), Some(&"defi".to_string()));
}

#[test]
fn test_context_serialization_roundtrip() {
    let context = PolicyContext::new(
        TransactionContext::transfer("137", "0xsender", "0xreceiver", "5000000"),
        SignerContext::new("key-2", "0xpubkey", "ed25519", "production")
            .with_user_id("user-42")
            .with_session_id("sess-99")
            .with_roles(vec!["admin".to_string(), "signer".to_string()])
            .with_label("tier", "premium"),
        EnvironmentContext::new("req-42").with_source_ip("192.168.1.100"),
    )
    .with_metadata("custom", "data");

    let bytes = context.to_json_bytes().unwrap();
    let deserialized = PolicyContext::from_json_bytes(&bytes).unwrap();

    assert_eq!(deserialized.transaction.chain_id, "137");
    assert_eq!(deserialized.transaction.value, "5000000");
    assert_eq!(deserialized.signer.key_id, "key-2");
    assert_eq!(deserialized.signer.namespace, "production");
    assert_eq!(deserialized.signer.user_id, Some("user-42".to_string()));
    assert_eq!(deserialized.signer.session_id, Some("sess-99".to_string()));
    assert!(deserialized.signer.roles.contains(&"admin".to_string()));
    assert_eq!(
        deserialized.signer.labels.get("tier"),
        Some(&"premium".to_string())
    );
    assert_eq!(
        deserialized.environment.source_ip,
        Some("192.168.1.100".to_string())
    );
    assert_eq!(
        deserialized.metadata.get("custom"),
        Some(&"data".to_string())
    );
}

#[test]
fn test_transaction_context_transfer() {
    let tx = TransactionContext::transfer("1", "0xfrom", "0xto", "1000000000000000000");

    assert_eq!(tx.tx_type, "transfer");
    assert_eq!(tx.chain_id, "1");
    assert_eq!(tx.from, "0xfrom");
    assert_eq!(tx.to, Some("0xto".to_string()));
    assert_eq!(tx.value, "1000000000000000000");
    assert!(tx.data.is_none());
    assert!(tx.gas_limit.is_none());
    assert!(tx.function_selector.is_none());
    assert!(tx.token_transfers.is_empty());
}

#[test]
fn test_transaction_context_contract_call() {
    let tx = TransactionContext::contract_call(
        "1",
        "0xsender",
        "0xcontract",
        "0xa9059cbb000000000000000000000000recipient",
    );

    assert_eq!(tx.tx_type, "contract_call");
    assert_eq!(tx.function_selector, Some("0xa9059cbb".to_string()));
    assert_eq!(tx.value, "0");
    assert!(tx.data.is_some());
}

#[test]
fn test_transaction_context_short_data_no_selector() {
    let tx = TransactionContext::contract_call("1", "0xsender", "0xcontract", "0xabcd");

    // Data is only 6 chars, shorter than 10, so no selector
    assert!(tx.function_selector.is_none());
}

#[test]
fn test_signer_context_basic() {
    let signer = SignerContext::new("key-1", "0x04abcd", "secp256k1", "default");

    assert_eq!(signer.key_id, "key-1");
    assert_eq!(signer.public_key, "0x04abcd");
    assert_eq!(signer.key_type, "secp256k1");
    assert_eq!(signer.namespace, "default");
    assert!(signer.user_id.is_none());
    assert!(signer.session_id.is_none());
    assert!(signer.roles.is_empty());
    assert!(signer.labels.is_empty());
}

#[test]
fn test_signer_context_full() {
    let signer = SignerContext::new("key-5", "0xpubkey", "ed25519", "production")
        .with_user_id("alice")
        .with_session_id("sess-abc")
        .with_roles(vec!["trader".to_string(), "viewer".to_string()])
        .with_label("department", "trading")
        .with_label("risk_level", "high");

    assert_eq!(signer.user_id, Some("alice".to_string()));
    assert_eq!(signer.session_id, Some("sess-abc".to_string()));
    assert_eq!(signer.roles.len(), 2);
    assert_eq!(
        signer.labels.get("department"),
        Some(&"trading".to_string())
    );
    assert_eq!(signer.labels.get("risk_level"), Some(&"high".to_string()));
}

#[test]
fn test_environment_context_basic() {
    let env = EnvironmentContext::new("req-hello");

    assert_eq!(env.request_id, "req-hello");
    assert!(!env.is_simulation);
    assert!(env.source_ip.is_none());
    assert!(env.user_agent.is_none());
    assert!(env.geo_location.is_none());
    assert!(env.timestamp > 0);
}

#[test]
fn test_environment_context_simulation() {
    let env = EnvironmentContext::new("req-sim").as_simulation();
    assert!(env.is_simulation);
}

#[test]
fn test_environment_context_with_source_ip() {
    let env = EnvironmentContext::new("req-ip").with_source_ip("10.0.0.1");
    assert_eq!(env.source_ip, Some("10.0.0.1".to_string()));
}

// ---------------------------------------------------------------------------
// 5. Policy Metadata
// ---------------------------------------------------------------------------

#[test]
fn test_policy_metadata_filters() {
    let metadata = make_metadata("filtered", "Filtered")
        .for_namespace("production")
        .for_namespace("staging")
        .for_chain("1")
        .for_chain("137")
        .for_key("key-specific")
        .for_tx_type("transfer");

    // Matches production, chain 1, specific key, transfer
    assert!(metadata.applies_to("production", "key-specific", "1", "transfer"));

    // Wrong namespace
    assert!(!metadata.applies_to("development", "key-specific", "1", "transfer"));

    // Wrong chain
    assert!(!metadata.applies_to("production", "key-specific", "56", "transfer"));

    // Wrong key
    assert!(!metadata.applies_to("production", "other-key", "1", "transfer"));

    // Wrong tx type
    assert!(!metadata.applies_to("production", "key-specific", "1", "contract_call"));
}

#[test]
fn test_policy_metadata_empty_filters_match_all() {
    let metadata = make_metadata("open", "Open Policy");

    // Empty filters should match everything
    assert!(metadata.applies_to("any-ns", "any-key", "any-chain", "any-type"));
}

#[test]
fn test_policy_metadata_tags() {
    let metadata = make_metadata("tagged", "Tagged")
        .with_tag("compliance")
        .with_tag("defi");

    assert!(metadata.tags.contains("compliance"));
    assert!(metadata.tags.contains("defi"));
    assert!(!metadata.tags.contains("nft"));
}

#[test]
fn test_policy_metadata_description_and_author() {
    let metadata = make_metadata("desc", "Described")
        .with_description("A thorough description of this policy")
        .with_author("security-team");

    assert_eq!(
        metadata.description,
        "A thorough description of this policy"
    );
    assert_eq!(metadata.author, Some("security-team".to_string()));
}

#[test]
fn test_policy_metadata_priority() {
    let meta1 = make_metadata("p1", "P1").with_priority(5);
    let meta2 = make_metadata("p2", "P2").with_priority(-1);
    let meta3 = make_metadata("p3", "P3").with_priority(100);

    assert_eq!(meta1.priority, 5);
    assert_eq!(meta2.priority, -1);
    assert_eq!(meta3.priority, 100);
}

#[test]
fn test_policy_decision_from_i32() {
    assert_eq!(PolicyDecision::from_i32(0), Some(PolicyDecision::Deny));
    assert_eq!(PolicyDecision::from_i32(1), Some(PolicyDecision::Allow));
    assert_eq!(
        PolicyDecision::from_i32(2),
        Some(PolicyDecision::RequireApproval)
    );
    assert_eq!(PolicyDecision::from_i32(-1), None);
    assert_eq!(PolicyDecision::from_i32(3), None);
    assert_eq!(PolicyDecision::from_i32(99), None);
}

#[test]
fn test_policy_decision_display() {
    assert_eq!(PolicyDecision::Deny.to_string(), "deny");
    assert_eq!(PolicyDecision::Allow.to_string(), "allow");
    assert_eq!(
        PolicyDecision::RequireApproval.to_string(),
        "require_approval"
    );
}

#[test]
fn test_policy_decision_predicates() {
    assert!(PolicyDecision::Allow.is_allowed());
    assert!(!PolicyDecision::Allow.is_denied());
    assert!(!PolicyDecision::Allow.requires_approval());

    assert!(PolicyDecision::Deny.is_denied());
    assert!(!PolicyDecision::Deny.is_allowed());

    assert!(PolicyDecision::RequireApproval.requires_approval());
    assert!(!PolicyDecision::RequireApproval.is_allowed());
}

#[test]
fn test_policy_id_conversions() {
    let id1 = PolicyId::new("test");
    assert_eq!(id1.as_str(), "test");
    assert_eq!(id1.to_string(), "test");

    let id2: PolicyId = "from-str".into();
    assert_eq!(id2.as_str(), "from-str");

    let id3: PolicyId = String::from("from-string").into();
    assert_eq!(id3.as_str(), "from-string");
}

#[test]
fn test_policy_compute_hash() {
    let wasm = allow_wasm();
    let hash = Policy::compute_hash(&wasm);

    // SHA-256 produces 32 bytes = 64 hex chars
    assert_eq!(hash.len(), 64);

    // Same input produces same hash
    let hash2 = Policy::compute_hash(&wasm);
    assert_eq!(hash, hash2);

    // Different input produces different hash
    let hash3 = Policy::compute_hash(&deny_wasm());
    assert_ne!(hash, hash3);
}

// ---------------------------------------------------------------------------
// 6. Host Functions
// ---------------------------------------------------------------------------

#[test]
fn test_host_functions_transaction_accessors() {
    let context = PolicyContext::new(
        TransactionContext::transfer("42", "0xaaa", "0xbbb", "999"),
        SignerContext::new("k1", "0xpub", "secp256k1", "ns1"),
        EnvironmentContext::new("req-1"),
    );

    let host = HostFunctions::new(context);

    assert_eq!(host.get_chain_id(), "42");
    assert_eq!(host.get_tx_from(), "0xaaa");
    assert_eq!(host.get_tx_to(), Some("0xbbb".to_string()));
    assert_eq!(host.get_tx_value(), "999");
    assert_eq!(host.get_tx_type(), "transfer");
    assert_eq!(host.get_key_id(), "k1");
    assert_eq!(host.get_namespace(), "ns1");
}

#[test]
fn test_host_functions_roles() {
    let context = PolicyContext::new(
        TransactionContext::transfer("1", "0xa", "0xb", "0"),
        SignerContext::new("k1", "0xp", "secp256k1", "default")
            .with_roles(vec!["admin".to_string(), "signer".to_string()]),
        EnvironmentContext::new("req-1"),
    );

    let host = HostFunctions::new(context);

    assert!(host.has_role("admin"));
    assert!(host.has_role("signer"));
    assert!(!host.has_role("viewer"));
}

#[test]
fn test_host_functions_labels() {
    let context = PolicyContext::new(
        TransactionContext::transfer("1", "0xa", "0xb", "0"),
        SignerContext::new("k1", "0xp", "secp256k1", "default").with_label("env", "prod"),
        EnvironmentContext::new("req-1"),
    );

    let host = HostFunctions::new(context);

    assert_eq!(host.get_label("env"), Some("prod".to_string()));
    assert_eq!(host.get_label("missing"), None);
}

#[test]
fn test_host_functions_metadata() {
    let context = PolicyContext::new(
        TransactionContext::transfer("1", "0xa", "0xb", "0"),
        SignerContext::new("k1", "0xp", "secp256k1", "default"),
        EnvironmentContext::new("req-1"),
    )
    .with_metadata("custom_key", "custom_val");

    let host = HostFunctions::new(context);

    assert_eq!(
        host.get_metadata("custom_key"),
        Some("custom_val".to_string())
    );
    assert_eq!(host.get_metadata("absent"), None);
}

#[test]
fn test_host_functions_logging() {
    let host = HostFunctions::new(test_context());

    host.log(0, "debug message");
    host.log(1, "info message");
    host.log(2, "warn message");
    host.log(3, "error message");

    let logs = host.logs();
    assert_eq!(logs.len(), 4);
    assert_eq!(logs[0].level, LogLevel::Debug);
    assert_eq!(logs[1].level, LogLevel::Info);
    assert_eq!(logs[2].level, LogLevel::Warn);
    assert_eq!(logs[3].level, LogLevel::Error);
    assert_eq!(logs[0].message, "debug message");
}

#[test]
fn test_host_functions_log_limit() {
    let host = HostFunctions::new(test_context());

    // Default max is 100 logs
    for i in 0..150 {
        host.log(1, &format!("log {}", i));
    }

    let logs = host.logs();
    assert_eq!(logs.len(), 100);
}

#[test]
fn test_host_functions_call_counting() {
    let host = HostFunctions::new(test_context());

    assert_eq!(host.call_count(), 0);

    host.get_chain_id();
    host.get_tx_from();
    host.get_key_id();

    assert_eq!(host.call_count(), 3);
}

#[test]
fn test_host_functions_compare_big_int() {
    let host = HostFunctions::new(test_context());

    assert_eq!(host.compare_big_int("100", "200"), -1);
    assert_eq!(host.compare_big_int("200", "100"), 1);
    assert_eq!(host.compare_big_int("100", "100"), 0);
    assert_eq!(
        host.compare_big_int("1000000000000000000", "999999999999999999"),
        1
    );
}

#[test]
fn test_host_functions_address_in_list() {
    let host = HostFunctions::new(test_context());

    let allowlist = "0xABC123, 0xDEF456, 0x789012";

    // Case-insensitive matching
    assert!(host.address_in_list("0xabc123", allowlist));
    assert!(host.address_in_list("0xABC123", allowlist));
    assert!(host.address_in_list("0xdef456", allowlist));
    assert!(!host.address_in_list("0x000000", allowlist));
}

#[test]
fn test_host_functions_is_simulation() {
    let normal_ctx = test_context();
    let host_normal = HostFunctions::new(normal_ctx);
    assert!(!host_normal.is_simulation());

    let sim_ctx = PolicyContext::new(
        TransactionContext::transfer("1", "0xa", "0xb", "0"),
        SignerContext::new("k1", "0xp", "secp256k1", "default"),
        EnvironmentContext::new("req-sim").as_simulation(),
    );
    let host_sim = HostFunctions::new(sim_ctx);
    assert!(host_sim.is_simulation());
}

#[test]
fn test_host_functions_timestamp() {
    let host = HostFunctions::new(test_context());
    let ts = host.get_timestamp();
    // Should be a recent Unix timestamp
    assert!(ts > 1700000000);
}

#[test]
fn test_host_state_alloc_pos() {
    let host = HostFunctions::new(test_context());
    let state = HostState::new(host, wasmtime::StoreLimitsBuilder::new().build());
    // Default alloc position is after the stack
    assert_eq!(state.alloc_pos, 16384);
}

#[test]
fn test_log_level_from_i32() {
    assert_eq!(LogLevel::from_i32(0), Some(LogLevel::Debug));
    assert_eq!(LogLevel::from_i32(1), Some(LogLevel::Info));
    assert_eq!(LogLevel::from_i32(2), Some(LogLevel::Warn));
    assert_eq!(LogLevel::from_i32(3), Some(LogLevel::Error));
    assert_eq!(LogLevel::from_i32(4), None);
    assert_eq!(LogLevel::from_i32(-1), None);
}

// ---------------------------------------------------------------------------
// 7. ABI Version and Constants
// ---------------------------------------------------------------------------

#[test]
fn test_abi_version() {
    assert_eq!(hsm_wasm_policy::ABI_VERSION, 1);
}

#[test]
fn test_max_policy_size() {
    assert_eq!(hsm_wasm_policy::MAX_POLICY_SIZE, 1024 * 1024);
}
