//! Resource limits for policy execution.
//!
//! This module defines configurable limits for WASM policy execution
//! to prevent runaway policies from consuming excessive resources.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Resource limits for policy execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum execution time.
    pub max_execution_time: Duration,

    /// Maximum memory in bytes.
    pub max_memory_bytes: usize,

    /// Maximum fuel (instruction count).
    /// wasmtime uses fuel to limit execution.
    pub max_fuel: u64,

    /// Maximum stack size in bytes.
    pub max_stack_size: usize,

    /// Maximum number of tables.
    pub max_tables: u32,

    /// Maximum table elements.
    pub max_table_elements: u32,

    /// Maximum number of memories.
    pub max_memories: u32,

    /// Maximum number of instances.
    pub max_instances: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            // 100ms default timeout
            max_execution_time: Duration::from_millis(100),
            // 16 MB memory limit
            max_memory_bytes: 16 * 1024 * 1024,
            // 10 million instructions (fuel)
            max_fuel: 10_000_000,
            // 1 MB stack
            max_stack_size: 1024 * 1024,
            // Reasonable defaults for tables/memories
            max_tables: 10,
            max_table_elements: 10_000,
            max_memories: 1,
            max_instances: 10,
        }
    }
}

impl ResourceLimits {
    /// Create new resource limits with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create strict limits for untrusted policies.
    pub fn strict() -> Self {
        Self {
            max_execution_time: Duration::from_millis(50),
            max_memory_bytes: 4 * 1024 * 1024, // 4 MB
            max_fuel: 1_000_000,               // 1 million instructions
            max_stack_size: 512 * 1024,        // 512 KB
            max_tables: 1,
            max_table_elements: 1_000,
            max_memories: 1,
            max_instances: 1,
        }
    }

    /// Create relaxed limits for trusted policies.
    pub fn relaxed() -> Self {
        Self {
            max_execution_time: Duration::from_millis(1000),
            max_memory_bytes: 64 * 1024 * 1024, // 64 MB
            max_fuel: 100_000_000,              // 100 million instructions
            max_stack_size: 2 * 1024 * 1024,    // 2 MB
            max_tables: 100,
            max_table_elements: 100_000,
            max_memories: 10,
            max_instances: 100,
        }
    }

    /// Set maximum execution time.
    pub fn with_execution_time(mut self, duration: Duration) -> Self {
        self.max_execution_time = duration;
        self
    }

    /// Set maximum memory.
    pub fn with_memory(mut self, bytes: usize) -> Self {
        self.max_memory_bytes = bytes;
        self
    }

    /// Set maximum fuel.
    pub fn with_fuel(mut self, fuel: u64) -> Self {
        self.max_fuel = fuel;
        self
    }
}

/// Execution statistics from a policy run.
#[derive(Debug, Clone, Default)]
pub struct ExecutionStats {
    /// Fuel consumed.
    pub fuel_consumed: u64,

    /// Peak memory usage in bytes.
    pub peak_memory_bytes: usize,

    /// Execution time.
    pub execution_time: Duration,

    /// Number of host function calls.
    pub host_calls: u64,
}

impl ExecutionStats {
    /// Create new execution stats.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record fuel consumption.
    pub fn with_fuel(mut self, fuel: u64) -> Self {
        self.fuel_consumed = fuel;
        self
    }

    /// Record execution time.
    pub fn with_time(mut self, duration: Duration) -> Self {
        self.execution_time = duration;
        self
    }

    /// Check if limits were exceeded.
    pub fn check_limits(&self, limits: &ResourceLimits) -> Option<LimitViolation> {
        if self.fuel_consumed > limits.max_fuel {
            return Some(LimitViolation::Fuel {
                used: self.fuel_consumed,
                limit: limits.max_fuel,
            });
        }

        if self.peak_memory_bytes > limits.max_memory_bytes {
            return Some(LimitViolation::Memory {
                used: self.peak_memory_bytes,
                limit: limits.max_memory_bytes,
            });
        }

        if self.execution_time > limits.max_execution_time {
            return Some(LimitViolation::Time {
                used: self.execution_time,
                limit: limits.max_execution_time,
            });
        }

        None
    }
}

/// Type of resource limit violation.
#[derive(Debug, Clone)]
pub enum LimitViolation {
    /// Fuel limit exceeded.
    Fuel { used: u64, limit: u64 },
    /// Memory limit exceeded.
    Memory { used: usize, limit: usize },
    /// Time limit exceeded.
    Time { used: Duration, limit: Duration },
}

impl std::fmt::Display for LimitViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LimitViolation::Fuel { used, limit } => {
                write!(f, "Fuel limit exceeded: used {}, limit {}", used, limit)
            }
            LimitViolation::Memory { used, limit } => {
                write!(
                    f,
                    "Memory limit exceeded: used {} bytes, limit {} bytes",
                    used, limit
                )
            }
            LimitViolation::Time { used, limit } => {
                write!(f, "Time limit exceeded: used {:?}, limit {:?}", used, limit)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_limits() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_execution_time, Duration::from_millis(100));
        assert_eq!(limits.max_memory_bytes, 16 * 1024 * 1024);
    }

    #[test]
    fn test_strict_limits() {
        let limits = ResourceLimits::strict();
        assert!(limits.max_memory_bytes < ResourceLimits::default().max_memory_bytes);
        assert!(limits.max_fuel < ResourceLimits::default().max_fuel);
    }

    #[test]
    fn test_limit_check() {
        let limits = ResourceLimits::new().with_fuel(1000);
        let stats = ExecutionStats::new().with_fuel(2000);

        let violation = stats.check_limits(&limits);
        assert!(matches!(violation, Some(LimitViolation::Fuel { .. })));
    }
}
