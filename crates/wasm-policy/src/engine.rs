//! Policy execution engine.
//!
//! This module provides the main policy evaluation engine that executes
//! WASM policies in a sandboxed environment.

use crate::context::PolicyContext;
use crate::error::{PolicyError, Result};
use crate::host::{HostFunctions, HostState};
use crate::limits::{ExecutionStats, ResourceLimits};
use crate::policy::{Policy, PolicyDecision, PolicyId};
use crate::store::PolicyStore;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};
use wasmtime::{Engine, Instance, Linker, Store, TypedFunc};

/// Policy evaluation engine.
pub struct PolicyEngine {
    /// Wasmtime engine.
    engine: Engine,

    /// Policy store.
    store: Arc<PolicyStore>,

    /// Default resource limits.
    default_limits: ResourceLimits,
}

impl PolicyEngine {
    /// Create a new policy engine.
    pub fn new(default_limits: ResourceLimits) -> Result<Self> {
        let engine = Self::create_engine(&default_limits)?;
        let store = Arc::new(PolicyStore::new(engine.clone())?);

        Ok(Self {
            engine,
            store,
            default_limits,
        })
    }

    /// Create a policy engine with a custom store.
    pub fn with_store(store: Arc<PolicyStore>, default_limits: ResourceLimits) -> Result<Self> {
        let engine = Self::create_engine(&default_limits)?;

        Ok(Self {
            engine,
            store,
            default_limits,
        })
    }

    /// Create configured wasmtime engine.
    fn create_engine(limits: &ResourceLimits) -> Result<Engine> {
        let mut config = wasmtime::Config::new();

        // Enable fuel consumption for instruction limiting
        config.consume_fuel(true);

        // Memory limits
        config.max_wasm_stack(limits.max_stack_size);

        // Compilation settings for security
        config.wasm_reference_types(false);
        config.wasm_simd(false);
        config.wasm_relaxed_simd(false);
        config.wasm_bulk_memory(true);
        config.wasm_multi_value(true);
        config.wasm_threads(false);

        Engine::new(&config).map_err(|e| PolicyError::Internal(e.to_string()))
    }

    /// Get the policy store.
    pub fn store(&self) -> &Arc<PolicyStore> {
        &self.store
    }

    /// Register a policy.
    pub fn register_policy(&self, policy: Policy) -> Result<()> {
        self.store.register(policy)
    }

    /// Evaluate a single policy.
    pub fn evaluate_policy(
        &self,
        policy_id: &PolicyId,
        context: &PolicyContext,
    ) -> Result<EvaluationResult> {
        let policy = self
            .store
            .get(policy_id)
            .ok_or_else(|| PolicyError::NotFound(policy_id.to_string()))?;

        if !policy.metadata.enabled {
            return Err(PolicyError::PolicyDisabled(policy_id.to_string()));
        }

        let limits = policy
            .metadata
            .resource_limits
            .as_ref()
            .unwrap_or(&self.default_limits)
            .clone();

        self.execute_policy(&policy, context, &limits)
    }

    /// Evaluate all applicable policies for a context.
    pub fn evaluate(&self, context: &PolicyContext) -> Result<AggregatedResult> {
        let namespace = &context.signer.namespace;
        let key_id = &context.signer.key_id;
        let chain_id = &context.transaction.chain_id;
        let tx_type = &context.transaction.tx_type;

        let policies = self
            .store
            .find_applicable(namespace, key_id, chain_id, tx_type);

        if policies.is_empty() {
            debug!("No applicable policies found, defaulting to allow");
            return Ok(AggregatedResult {
                decision: PolicyDecision::Allow,
                results: vec![],
                total_time_ms: 0,
            });
        }

        let start = Instant::now();
        let mut results = Vec::with_capacity(policies.len());
        let mut final_decision = PolicyDecision::Allow;

        for policy in &policies {
            let limits = policy
                .metadata
                .resource_limits
                .as_ref()
                .unwrap_or(&self.default_limits)
                .clone();

            match self.execute_policy(policy, context, &limits) {
                Ok(result) => {
                    // Update final decision based on policy result
                    match result.decision {
                        PolicyDecision::Deny => {
                            final_decision = PolicyDecision::Deny;
                            results.push(result);
                            // Short-circuit on deny
                            break;
                        }
                        PolicyDecision::RequireApproval => {
                            if final_decision != PolicyDecision::Deny {
                                final_decision = PolicyDecision::RequireApproval;
                            }
                            results.push(result);
                        }
                        PolicyDecision::Allow => {
                            results.push(result);
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        policy_id = %policy.metadata.id,
                        error = %e,
                        "Policy evaluation failed"
                    );
                    // Treat errors as deny for safety
                    results.push(EvaluationResult {
                        policy_id: policy.metadata.id.clone(),
                        decision: PolicyDecision::Deny,
                        stats: ExecutionStats::default(),
                        error: Some(e.to_string()),
                        logs: vec![],
                    });
                    final_decision = PolicyDecision::Deny;
                    break;
                }
            }
        }

        let total_time_ms = start.elapsed().as_millis() as u64;

        info!(
            decision = %final_decision,
            policies_evaluated = results.len(),
            total_time_ms,
            "Policy evaluation complete"
        );

        Ok(AggregatedResult {
            decision: final_decision,
            results,
            total_time_ms,
        })
    }

    /// Execute a single policy and return the result.
    fn execute_policy(
        &self,
        policy: &Policy,
        context: &PolicyContext,
        limits: &ResourceLimits,
    ) -> Result<EvaluationResult> {
        let start = Instant::now();
        let policy_id = policy.metadata.id.clone();

        debug!(policy_id = %policy_id, "Executing policy");

        // Get compiled module
        let module = self.store.get_module(&policy_id)?;

        // Create host functions
        let host = HostFunctions::new(context.clone());
        let host_state = HostState::new(host.clone());

        // Create store with fuel
        let mut store = Store::new(&self.engine, host_state);
        store.set_fuel(limits.max_fuel)?;

        // Create linker (no host imports for now - simple policies only)
        let linker = Linker::new(&self.engine);

        // Instantiate module
        let instance = linker.instantiate(&mut store, &module)?;

        // Get evaluate function
        let evaluate: TypedFunc<(i32, i32), i32> = instance
            .get_typed_func(&mut store, "evaluate")
            .map_err(|e| PolicyError::MissingExport(format!("evaluate: {}", e)))?;

        // Serialize context to memory
        let context_bytes = context.to_json_bytes()?;
        let (context_ptr, context_len) =
            self.write_to_memory(&mut store, &instance, &context_bytes)?;

        // Call the evaluate function
        let result = evaluate.call(&mut store, (context_ptr, context_len));

        let execution_time = start.elapsed();
        let fuel_consumed = limits.max_fuel - store.get_fuel().unwrap_or(0);

        // Build stats
        let stats = ExecutionStats {
            fuel_consumed,
            peak_memory_bytes: 0, // TODO: track memory
            execution_time,
            host_calls: host.call_count(),
        };

        // Check limits
        if let Some(violation) = stats.check_limits(limits) {
            return Err(PolicyError::ResourceLimitExceeded(violation.to_string()));
        }

        // Process result
        match result {
            Ok(decision_value) => {
                let decision = PolicyDecision::from_i32(decision_value).ok_or_else(|| {
                    PolicyError::InvalidResult(format!(
                        "Unknown decision value: {}",
                        decision_value
                    ))
                })?;

                debug!(
                    policy_id = %policy_id,
                    decision = %decision,
                    fuel_consumed,
                    time_ms = execution_time.as_millis(),
                    "Policy executed successfully"
                );

                Ok(EvaluationResult {
                    policy_id,
                    decision,
                    stats,
                    error: None,
                    logs: host.logs().into_iter().map(|l| l.message).collect(),
                })
            }
            Err(e) => {
                // Check if it was a fuel exhaustion
                if e.to_string().contains("fuel") {
                    Err(PolicyError::GasLimitExceeded {
                        used: fuel_consumed,
                        limit: limits.max_fuel,
                    })
                } else {
                    Err(PolicyError::ExecutionFailed(e.to_string()))
                }
            }
        }
    }

    /// Write data to WASM memory.
    fn write_to_memory(
        &self,
        store: &mut Store<HostState>,
        instance: &Instance,
        data: &[u8],
    ) -> Result<(i32, i32)> {
        let memory = instance
            .get_memory(&mut *store, "memory")
            .ok_or_else(|| PolicyError::ExecutionFailed("No memory export".into()))?;

        // Simple allocation: write to beginning of memory after stack
        // In production, would use a proper allocator
        let ptr = store.data().alloc_pos;
        let len = data.len() as i32;

        {
            let mem_data = memory.data_mut(&mut *store);
            if (ptr as usize + data.len()) > mem_data.len() {
                return Err(PolicyError::MemoryLimitExceeded {
                    used: ptr as usize + data.len(),
                    limit: mem_data.len(),
                });
            }

            mem_data[ptr as usize..ptr as usize + data.len()].copy_from_slice(data);
        }

        // Update allocator position in host state
        store.data_mut().alloc_pos = ptr + len;

        Ok((ptr, len))
    }

    /// Simulate policy evaluation (dry run).
    pub fn simulate(&self, context: &PolicyContext) -> Result<AggregatedResult> {
        let mut sim_context = context.clone();
        sim_context.environment.is_simulation = true;
        self.evaluate(&sim_context)
    }
}

/// Result of evaluating a single policy.
#[derive(Debug, Clone)]
pub struct EvaluationResult {
    /// Policy that was evaluated.
    pub policy_id: PolicyId,

    /// Decision from the policy.
    pub decision: PolicyDecision,

    /// Execution statistics.
    pub stats: ExecutionStats,

    /// Error message if policy failed.
    pub error: Option<String>,

    /// Log messages from the policy.
    pub logs: Vec<String>,
}

/// Aggregated result from evaluating all applicable policies.
#[derive(Debug, Clone)]
pub struct AggregatedResult {
    /// Final decision after all policies.
    pub decision: PolicyDecision,

    /// Individual policy results.
    pub results: Vec<EvaluationResult>,

    /// Total evaluation time in milliseconds.
    pub total_time_ms: u64,
}

impl AggregatedResult {
    /// Check if the transaction is allowed.
    pub fn is_allowed(&self) -> bool {
        self.decision.is_allowed()
    }

    /// Check if the transaction is denied.
    pub fn is_denied(&self) -> bool {
        self.decision.is_denied()
    }

    /// Check if additional approval is required.
    pub fn requires_approval(&self) -> bool {
        self.decision.requires_approval()
    }

    /// Get the policy that caused a deny decision.
    pub fn denying_policy(&self) -> Option<&PolicyId> {
        self.results
            .iter()
            .find(|r| r.decision.is_denied())
            .map(|r| &r.policy_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{EnvironmentContext, SignerContext, TransactionContext};
    use crate::policy::PolicyMetadata;

    fn test_context() -> PolicyContext {
        PolicyContext::new(
            TransactionContext::transfer("1", "0xfrom", "0xto", "1000000000000000000"),
            SignerContext::new("key-1", "0x04...", "secp256k1", "default"),
            EnvironmentContext::new("req-123"),
        )
    }

    // WASM module that always allows
    fn allow_policy_wasm() -> Vec<u8> {
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

    // WASM module that always denies
    fn deny_policy_wasm() -> Vec<u8> {
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

    // WASM module that requires approval
    fn approval_policy_wasm() -> Vec<u8> {
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

    #[test]
    fn test_engine_creation() {
        let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();
        assert!(engine.store().list().is_empty());
    }

    #[test]
    fn test_evaluate_allow_policy() {
        let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();

        let metadata = PolicyMetadata::new(
            PolicyId::new("allow-all"),
            "Allow All",
            "1.0.0",
            "hash",
            100,
        );
        let policy = Policy::new(metadata, allow_policy_wasm());
        engine.register_policy(policy).unwrap();

        let result = engine.evaluate(&test_context()).unwrap();
        assert!(result.is_allowed());
    }

    #[test]
    fn test_evaluate_deny_policy() {
        let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();

        let metadata =
            PolicyMetadata::new(PolicyId::new("deny-all"), "Deny All", "1.0.0", "hash", 100);
        let policy = Policy::new(metadata, deny_policy_wasm());
        engine.register_policy(policy).unwrap();

        let result = engine.evaluate(&test_context()).unwrap();
        assert!(result.is_denied());
    }

    #[test]
    fn test_evaluate_approval_policy() {
        let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();

        let metadata = PolicyMetadata::new(
            PolicyId::new("require-approval"),
            "Require Approval",
            "1.0.0",
            "hash",
            100,
        );
        let policy = Policy::new(metadata, approval_policy_wasm());
        engine.register_policy(policy).unwrap();

        let result = engine.evaluate(&test_context()).unwrap();
        assert!(result.requires_approval());
    }

    #[test]
    fn test_deny_overrides_allow() {
        let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();

        // Register allow policy with lower priority (higher number)
        let metadata1 = PolicyMetadata::new(
            PolicyId::new("allow-all"),
            "Allow All",
            "1.0.0",
            "hash1",
            100,
        )
        .with_priority(10);
        engine
            .register_policy(Policy::new(metadata1, allow_policy_wasm()))
            .unwrap();

        // Register deny policy with higher priority (lower number)
        let metadata2 =
            PolicyMetadata::new(PolicyId::new("deny-all"), "Deny All", "1.0.0", "hash2", 100)
                .with_priority(0);
        engine
            .register_policy(Policy::new(metadata2, deny_policy_wasm()))
            .unwrap();

        let result = engine.evaluate(&test_context()).unwrap();
        assert!(result.is_denied());
        assert_eq!(result.denying_policy().unwrap().as_str(), "deny-all");
    }

    #[test]
    fn test_no_policies_allows() {
        let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();

        let result = engine.evaluate(&test_context()).unwrap();
        assert!(result.is_allowed());
        assert!(result.results.is_empty());
    }

    #[test]
    fn test_simulation_flag() {
        let engine = PolicyEngine::new(ResourceLimits::default()).unwrap();

        let metadata = PolicyMetadata::new(
            PolicyId::new("allow-all"),
            "Allow All",
            "1.0.0",
            "hash",
            100,
        );
        engine
            .register_policy(Policy::new(metadata, allow_policy_wasm()))
            .unwrap();

        let result = engine.simulate(&test_context()).unwrap();
        assert!(result.is_allowed());
    }
}
