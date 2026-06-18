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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};
use wasmtime::{Engine, Instance, Linker, Store, StoreLimitsBuilder, TypedFunc};

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

        // Enable epoch-based interruption so an overrunning policy TRAPS once
        // its wall-clock deadline elapses. Fuel alone bounds *instructions* but
        // a policy can stall without consuming fuel proportional to wall time;
        // epoch checks let a background ticker forcibly interrupt execution. The
        // engine that compiles modules must have this enabled for the
        // instrumentation to be present at run time, which is why it lives here
        // in `create_engine`.
        config.epoch_interruption(true);

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

        // Build wasmtime resource limits from the policy's ResourceLimits. These
        // are enforced eagerly by wasmtime (via the limiter installed below) so
        // that memory.grow / table.grow and instance/table/memory creation that
        // would exceed the caps are rejected *before* they commit, rather than
        // being detected only post-hoc after up to ~4 GiB has already been
        // allocated. `trap_on_grow_failure(true)` makes an over-limit grow trap
        // instead of silently returning -1, so a policy cannot proceed on the
        // false assumption that the allocation succeeded.
        let store_limits = StoreLimitsBuilder::new()
            .memory_size(limits.max_memory_bytes)
            .table_elements(limits.max_table_elements as usize)
            .tables(limits.max_tables as usize)
            .memories(limits.max_memories as usize)
            .instances(limits.max_instances as usize)
            .trap_on_grow_failure(true)
            .build();
        let host_state = HostState::new(host.clone(), store_limits);

        // Create store with fuel
        let mut store = Store::new(&self.engine, host_state);
        store.set_fuel(limits.max_fuel)?;

        // Install the resource limiter BEFORE instantiation so growth/creation
        // limits apply to the module's declared memories/tables as well as any
        // runtime grow attempts.
        store.limiter(|state| &mut state.limits);

        // Arm an epoch-based deadline so an overrunning policy traps instead of
        // running unbounded. The store deadline is one tick out and configured
        // to trap; the `EpochTicker` guard advances the engine epoch once after
        // `max_execution_time`, tripping the trap. The guard signals + joins its
        // thread on drop, so it is always cleaned up on every return path
        // (including the `?` early-returns below) and can never fire
        // `increment_epoch()` after this call finishes — which would otherwise
        // corrupt an unrelated concurrent execution sharing the engine.
        store.epoch_deadline_trap();
        store.set_epoch_deadline(1);
        let _ticker = EpochTicker::spawn(self.engine.clone(), limits.max_execution_time);

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

        // Stop the ticker now (before reading stats) so it cannot fire a late
        // epoch increment; `drop` joins the thread.
        drop(_ticker);

        let execution_time = start.elapsed();
        let fuel_consumed = limits.max_fuel - store.get_fuel().unwrap_or(0);

        // Build stats
        let stats = ExecutionStats {
            fuel_consumed,
            peak_memory_bytes: instance
                .get_memory(&mut store, "memory")
                .map(|m| m.data_size(&store))
                .unwrap_or(0),
            execution_time,
            host_calls: host.call_count(),
        };

        // Process result.
        //
        // A trap (Err) is classified by its precise cause FIRST: an
        // epoch-deadline interruption or fuel exhaustion is the root reason the
        // policy stopped, and is more informative than the post-hoc limit
        // comparison below (which would otherwise shadow it, since a deadline
        // trap by definition means execution_time >= max_execution_time). The
        // post-hoc `check_limits` is retained as defense-in-depth on the SUCCESS
        // path, to fail closed when a policy returned a decision despite having
        // overrun a limit that the eager guards did not catch.
        match result {
            Ok(decision_value) => {
                // Defense-in-depth: a policy that returned a value but still
                // exceeded a limit (e.g. wall-clock time spent in host calls) is
                // rejected fail-closed.
                if let Some(violation) = stats.check_limits(limits) {
                    return Err(PolicyError::ResourceLimitExceeded(violation.to_string()));
                }

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
                // Detect fuel exhaustion / epoch-deadline interruption via the
                // typed trap rather than matching on the error's display string,
                // which is brittle across wasmtime versions and locales.
                match e.downcast_ref::<wasmtime::Trap>() {
                    Some(&wasmtime::Trap::OutOfFuel) => Err(PolicyError::GasLimitExceeded {
                        used: fuel_consumed,
                        limit: limits.max_fuel,
                    }),
                    // An epoch-deadline expiry surfaces as `Trap::Interrupt`:
                    // the policy overran its wall-clock deadline and was
                    // forcibly interrupted by the epoch ticker.
                    Some(&wasmtime::Trap::Interrupt) => Err(PolicyError::Timeout(
                        limits.max_execution_time.as_millis() as u64,
                    )),
                    _ => Err(PolicyError::ExecutionFailed(e.to_string())),
                }
            }
        }
    }

    /// Maximum heap size for WASM memory allocations (16 MB).
    const HEAP_MAX: usize = 16 * 1024 * 1024;

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

        // Validate data length fits in i32
        let len = i32::try_from(data.len()).map_err(|_| PolicyError::MemoryLimitExceeded {
            used: data.len(),
            limit: Self::HEAP_MAX,
        })?;

        // Simple allocation: write to beginning of memory after stack
        // In production, would use a proper allocator
        let ptr = store.data().alloc_pos;

        // Use checked arithmetic to prevent overflow
        let end_pos = ptr
            .checked_add(len)
            .ok_or(PolicyError::MemoryLimitExceeded {
                used: i32::MAX as usize,
                limit: Self::HEAP_MAX,
            })?;

        // Validate against heap maximum
        if (end_pos as usize) > Self::HEAP_MAX {
            return Err(PolicyError::MemoryLimitExceeded {
                used: end_pos as usize,
                limit: Self::HEAP_MAX,
            });
        }

        {
            let mem_data = memory.data_mut(&mut *store);
            if (end_pos as usize) > mem_data.len() {
                return Err(PolicyError::MemoryLimitExceeded {
                    used: end_pos as usize,
                    limit: mem_data.len(),
                });
            }

            mem_data[ptr as usize..end_pos as usize].copy_from_slice(data);
        }

        // Update allocator position in host state
        store.data_mut().alloc_pos = end_pos;

        Ok((ptr, len))
    }

    /// Simulate policy evaluation (dry run).
    pub fn simulate(&self, context: &PolicyContext) -> Result<AggregatedResult> {
        let mut sim_context = context.clone();
        sim_context.environment.is_simulation = true;
        self.evaluate(&sim_context)
    }
}

/// One-shot background thread that enforces a wall-clock deadline on a policy
/// execution by advancing the engine epoch once the deadline elapses.
///
/// The store is configured with `set_epoch_deadline(1)` and
/// `epoch_deadline_trap()`, so a single `increment_epoch()` after the deadline
/// traps the running policy with [`wasmtime::Trap::Interrupt`].
///
/// Dropping the ticker signals completion and joins the thread, guaranteeing
/// that the epoch is never incremented after the guarded call returns. This is
/// critical: a late increment would advance the shared engine epoch and could
/// prematurely trap an unrelated concurrent execution.
struct EpochTicker {
    done: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl EpochTicker {
    /// Spawn a ticker that advances `engine`'s epoch once after `deadline`.
    fn spawn(engine: Engine, deadline: std::time::Duration) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let handle = {
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                // Poll in small slices so we exit promptly once the guarded call
                // finishes, while still firing the epoch increment close to the
                // configured deadline if the policy overruns.
                let start = Instant::now();
                let slice = std::time::Duration::from_millis(1);
                while start.elapsed() < deadline {
                    if done.load(Ordering::Acquire) {
                        return;
                    }
                    std::thread::sleep(slice);
                }
                // Deadline elapsed and the call has not signalled completion:
                // advance the epoch to trip the store's deadline trap.
                if !done.load(Ordering::Acquire) {
                    engine.increment_epoch();
                }
            })
        };

        Self {
            done,
            handle: Some(handle),
        }
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        // Signal completion and join so the thread can never fire a late epoch
        // increment against a subsequent execution sharing the engine.
        self.done.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
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

    // WASM module that attempts to grow linear memory far beyond any sane cap
    // before returning "allow". `memory.grow` returns the previous page count on
    // success or -1 on failure; here we ignore the result and then write a byte
    // near the top of the requested region, so if the grow had actually
    // committed (the pre-fix behavior of allocating up to wasm's ceiling) the
    // store would hold a multi-hundred-MB allocation.
    fn memory_bomb_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"
            (module
                (memory (export "memory") 1)
                (func (export "evaluate") (param i32 i32) (result i32)
                    ;; Request 8192 additional 64 KiB pages = 512 MiB, far above
                    ;; the configured memory cap.
                    (drop (memory.grow (i32.const 8192)))
                    i32.const 1
                )
            )
        "#,
        )
        .unwrap()
    }

    // WASM module with an unconditional infinite loop. It never returns, so the
    // only way evaluation terminates is via fuel exhaustion or the epoch
    // deadline. We give it effectively unlimited fuel so the *deadline* is what
    // must interrupt it.
    fn infinite_loop_wasm() -> Vec<u8> {
        wat::parse_str(
            r#"
            (module
                (memory (export "memory") 1)
                (func (export "evaluate") (param i32 i32) (result i32)
                    (loop $forever
                        br $forever
                    )
                    i32.const 1
                )
            )
        "#,
        )
        .unwrap()
    }

    /// A policy that grows memory beyond the configured cap must be eagerly
    /// trapped (denied), NOT allowed to allocate up to wasm's 4 GiB ceiling and
    /// then be caught post-hoc. Proves the `StoreLimits` limiter is installed
    /// before instantiation with `trap_on_grow_failure`.
    #[test]
    fn test_memory_grow_beyond_cap_is_trapped() {
        // 16 MiB memory cap with generous fuel and time so that ONLY the memory
        // limit can be the cause of the trap.
        let limits = ResourceLimits::default()
            .with_memory(16 * 1024 * 1024)
            .with_fuel(1_000_000_000)
            .with_execution_time(std::time::Duration::from_secs(5));
        let engine = PolicyEngine::new(limits).unwrap();

        let metadata = PolicyMetadata::new(
            PolicyId::new("mem-bomb"),
            "Memory Bomb",
            "1.0.0",
            "hash",
            100,
        );
        engine
            .register_policy(Policy::new(metadata, memory_bomb_wasm()))
            .unwrap();

        // Single-policy path returns the raw error so we can assert the cause.
        let err = engine
            .evaluate_policy(&PolicyId::new("mem-bomb"), &test_context())
            .expect_err("memory grow beyond cap must fail, not allocate ~4 GiB");

        // The grow must trap *eagerly* (an `ExecutionFailed` from the wasm
        // `memory.grow` instruction trapping under `trap_on_grow_failure`),
        // proving the allocation was rejected BEFORE committing.
        //
        // Discriminator vs. the pre-fix behavior: without the installed limiter
        // the 512 MiB grow would succeed, the policy would return `Allow`, and
        // only the POST-HOC `check_limits` would catch it — surfacing as
        // `ResourceLimitExceeded` (a Memory violation) after ~512 MiB had
        // actually been committed. So `ResourceLimitExceeded` here would mean
        // the eager guard failed; we reject it explicitly.
        match err {
            PolicyError::ExecutionFailed(_) => {}
            PolicyError::ResourceLimitExceeded(_) => panic!(
                "memory grow was committed and only caught post-hoc \
                 (limiter not installed before instantiation): {err}"
            ),
            PolicyError::GasLimitExceeded { .. } => {
                panic!("expected memory grow trap, got fuel exhaustion: {err}")
            }
            PolicyError::Timeout(_) => {
                panic!("expected memory grow trap, got timeout: {err}")
            }
            other => panic!("unexpected error variant for memory bomb: {other}"),
        }

        // The aggregated path treats the failure as a deny (fail-closed).
        let agg = engine.evaluate(&test_context()).unwrap();
        assert!(
            agg.is_denied(),
            "memory-bomb policy must be denied, got {:?}",
            agg.decision
        );
    }

    /// A long-running policy must be interrupted by the wall-clock deadline via
    /// epoch interruption, surfacing as a `Timeout`. Fuel is set high enough
    /// that the loop would otherwise run far past the deadline.
    #[test]
    fn test_long_running_policy_interrupted_by_deadline() {
        // Very high fuel so fuel is NOT the limiter; short 50ms deadline.
        let limits = ResourceLimits::default()
            .with_fuel(u64::MAX)
            .with_execution_time(std::time::Duration::from_millis(50));
        let engine = PolicyEngine::new(limits).unwrap();

        let metadata = PolicyMetadata::new(
            PolicyId::new("infinite"),
            "Infinite Loop",
            "1.0.0",
            "hash",
            100,
        );
        engine
            .register_policy(Policy::new(metadata, infinite_loop_wasm()))
            .unwrap();

        let start = std::time::Instant::now();
        let err = engine
            .evaluate_policy(&PolicyId::new("infinite"), &test_context())
            .expect_err("infinite loop must be interrupted, not run forever");
        let elapsed = start.elapsed();

        // The epoch-deadline trap maps to Timeout. (If fuel had been the cause
        // it would be GasLimitExceeded — but we set fuel to u64::MAX.)
        assert!(
            matches!(err, PolicyError::Timeout(_)),
            "expected Timeout from epoch deadline, got {err}"
        );

        // It must have actually been interrupted promptly, not run unbounded.
        // Allow generous slack for CI scheduling jitter, but it must be far
        // below the multi-second range an unbounded loop would reach.
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "policy ran too long ({elapsed:?}); deadline did not interrupt it"
        );

        // Aggregated path: fail-closed deny.
        let agg = engine.evaluate(&test_context()).unwrap();
        assert!(agg.is_denied(), "interrupted policy must be denied");
    }
}
