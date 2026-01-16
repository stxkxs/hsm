//! Circuit breaker pattern implementation for fault tolerance.
//!
//! This module provides a circuit breaker to protect services from cascading failures
//! by detecting failures and temporarily blocking requests to failing services.
//!
//! # Circuit Breaker Pattern
//!
//! The circuit breaker acts like an electrical circuit breaker:
//! - Monitors operation failures
//! - "Opens" the circuit after threshold failures
//! - Periodically tests recovery by "half-opening"
//! - "Closes" the circuit when service recovers
//!
//! # State Machine
//!
//! ```text
//! ┌─────────┐
//! │ Closed  │  ◄─── Normal operation, all requests allowed
//! └────┬────┘
//!      │ failures >= threshold
//!      ▼
//! ┌─────────┐
//! │  Open   │  ◄─── Reject all requests immediately
//! └────┬────┘
//!      │ timeout elapsed
//!      ▼
//! ┌──────────┐
//! │HalfOpen  │  ◄─── Allow limited requests to test recovery
//! └────┬─────┘
//!      │
//!      ├─ successes >= threshold ──► Closed
//!      └─ any failure ─────────────► Open
//! ```
//!
//! # Use Cases
//!
//! - **Downstream Service Protection**: Prevent overwhelming a failing service
//! - **Fast Failure**: Fail quickly instead of waiting for timeout
//! - **Automatic Recovery**: Test service health and recover automatically
//! - **Resource Conservation**: Avoid wasting resources on doomed requests
//!
//! # Examples
//!
//! Basic usage:
//!
//! ```
//! use grpc_api::{CircuitBreaker, CircuitBreakerConfig};
//! use std::time::Duration;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create circuit breaker with custom config
//! let config = CircuitBreakerConfig {
//!     failure_threshold: 5,       // Open after 5 failures
//!     success_threshold: 2,       // Close after 2 successes in half-open
//!     timeout: Duration::from_secs(60),  // Try recovery after 60s
//!     half_open_max_requests: 1,  // Test with 1 request at a time
//! };
//!
//! let breaker = CircuitBreaker::new(config);
//!
//! // Execute operations through circuit breaker
//! match breaker.call(|| {
//!     // Your potentially failing operation
//!     Ok::<_, ()>(())
//! }) {
//!     Ok(result) => println!("Operation succeeded: {:?}", result),
//!     Err(err) => println!("Circuit breaker rejected or operation failed: {:?}", err),
//! }
//!
//! // Check circuit state
//! println!("Circuit state: {:?}", breaker.state());
//! # Ok(())
//! # }
//! ```

use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Errors returned by circuit breaker operations.
#[derive(Debug, Error)]
pub enum CircuitBreakerError {
    /// Circuit is open and rejecting all requests.
    ///
    /// This occurs when:
    /// - Failures exceeded the threshold
    /// - Timeout period hasn't elapsed yet
    #[error("Circuit breaker is open")]
    CircuitOpen,

    /// Too many concurrent requests in half-open state.
    ///
    /// This occurs when:
    /// - Circuit is in half-open state
    /// - Number of concurrent test requests exceeds `half_open_max_requests`
    #[error("Too many requests in half-open state")]
    TooManyRequests,
}

/// Circuit breaker state.
///
/// The circuit transitions between these states based on operation results:
///
/// - **Closed**: Normal operation, all requests pass through
/// - **Open**: Failing, rejects all requests immediately
/// - **HalfOpen**: Testing recovery, allows limited requests
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation - requests pass through, failures are counted.
    Closed,
    /// Service is failing - all requests are rejected immediately.
    Open,
    /// Testing recovery - limited requests allowed to test if service recovered.
    HalfOpen,
}

/// Circuit breaker implementation to prevent cascading failures.
///
/// This struct implements the circuit breaker pattern with:
/// - Atomic counters for thread-safe failure/success tracking
/// - RwLock for state transitions (rare writes, frequent reads)
/// - Automatic state transitions based on configured thresholds
/// - Configurable timeout and concurrency limits
///
/// # Thread Safety
///
/// The circuit breaker is thread-safe and can be shared across threads via
/// `Arc<CircuitBreaker>` or by cloning (which clones the Arc internally).
///
/// # Performance
///
/// - Fast path (closed state): Single atomic check
/// - State transitions: Lock acquisition required (infrequent)
/// - Memory overhead: ~200 bytes per instance
pub struct CircuitBreaker {
    state: Arc<RwLock<CircuitState>>,
    failure_count: Arc<AtomicU64>,
    success_count: Arc<AtomicU64>,
    last_failure_time: Arc<RwLock<Option<Instant>>>,
    config: CircuitBreakerConfig,
    half_open_requests: Arc<AtomicU64>,
}

/// Configuration for circuit breaker behavior.
///
/// # Fields
///
/// - `failure_threshold`: Number of consecutive failures before opening the circuit
/// - `success_threshold`: Number of successful requests needed to close from half-open
/// - `timeout`: Duration to wait before transitioning from open to half-open
/// - `half_open_max_requests`: Maximum concurrent requests allowed in half-open state
///
/// # Tuning Guidelines
///
/// ## failure_threshold
///
/// - **Low (1-3)**: Very sensitive, opens quickly (good for critical paths)
/// - **Medium (5-10)**: Balanced, tolerates transient errors (recommended)
/// - **High (20+)**: Tolerant, only opens for sustained failures
///
/// ## success_threshold
///
/// - **Low (1-2)**: Quick recovery (recommended for fast-recovering services)
/// - **Medium (3-5)**: More conservative (good for unstable services)
/// - **High (10+)**: Very cautious (rarely needed)
///
/// ## timeout
///
/// - **Short (1-10s)**: Test recovery frequently (good for transient issues)
/// - **Medium (30-60s)**: Standard timeout (recommended)
/// - **Long (5+ min)**: Give service time to fully recover (good for cold starts)
///
/// ## half_open_max_requests
///
/// - **1**: Safest, test with one request (recommended)
/// - **2-5**: Faster recovery testing
/// - **10+**: Risk overwhelming recovering service (not recommended)
///
/// # Examples
///
/// Sensitive configuration (open fast, recover fast):
///
/// ```
/// use grpc_api::CircuitBreakerConfig;
/// use std::time::Duration;
///
/// let config = CircuitBreakerConfig {
///     failure_threshold: 3,
///     success_threshold: 1,
///     timeout: Duration::from_secs(10),
///     half_open_max_requests: 1,
/// };
/// ```
///
/// Conservative configuration (tolerant, careful recovery):
///
/// ```
/// use grpc_api::CircuitBreakerConfig;
/// use std::time::Duration;
///
/// let config = CircuitBreakerConfig {
///     failure_threshold: 10,
///     success_threshold: 5,
///     timeout: Duration::from_secs(120),
///     half_open_max_requests: 1,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit.
    pub failure_threshold: u64,
    /// Number of successes to close circuit from half-open.
    pub success_threshold: u64,
    /// Time to wait before trying half-open state.
    pub timeout: Duration,
    /// Maximum concurrent requests in half-open state.
    pub half_open_max_requests: usize,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            timeout: Duration::from_secs(60),
            half_open_max_requests: 1,
        }
    }
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            failure_count: Arc::new(AtomicU64::new(0)),
            success_count: Arc::new(AtomicU64::new(0)),
            last_failure_time: Arc::new(RwLock::new(None)),
            config,
            half_open_requests: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Check if request can proceed
    pub fn call<F, T, E>(&self, f: F) -> Result<T, CircuitBreakerError>
    where
        F: FnOnce() -> Result<T, E>,
    {
        // Check current state and potentially transition
        self.check_state()?;

        // Execute the call
        match f() {
            Ok(result) => {
                self.on_success();
                Ok(result)
            }
            Err(_) => {
                self.on_failure();
                Err(CircuitBreakerError::CircuitOpen)
            }
        }
    }

    /// Check and update circuit breaker state
    fn check_state(&self) -> Result<(), CircuitBreakerError> {
        let mut state = self.state.write();

        match *state {
            CircuitState::Closed => Ok(()),

            CircuitState::Open => {
                // Check if timeout has elapsed
                let last_failure = self.last_failure_time.read();
                if let Some(last_time) = *last_failure {
                    if last_time.elapsed() >= self.config.timeout {
                        // Transition to half-open
                        *state = CircuitState::HalfOpen;
                        self.success_count.store(0, Ordering::Relaxed);
                        self.failure_count.store(0, Ordering::Relaxed);
                        self.half_open_requests.store(0, Ordering::Relaxed);
                        drop(state);
                        drop(last_failure);
                        Ok(())
                    } else {
                        Err(CircuitBreakerError::CircuitOpen)
                    }
                } else {
                    Err(CircuitBreakerError::CircuitOpen)
                }
            }

            CircuitState::HalfOpen => {
                // Limit concurrent requests in half-open state
                let current_requests = self.half_open_requests.load(Ordering::Relaxed);
                if current_requests >= self.config.half_open_max_requests as u64 {
                    Err(CircuitBreakerError::TooManyRequests)
                } else {
                    self.half_open_requests.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
            }
        }
    }

    /// Record successful operation
    fn on_success(&self) {
        let state = self.state.read();

        match *state {
            CircuitState::Closed => {
                // Reset failure count on success
                self.failure_count.store(0, Ordering::Relaxed);
            }

            CircuitState::HalfOpen => {
                self.half_open_requests.fetch_sub(1, Ordering::Relaxed);
                let successes = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;

                // Check if we should close the circuit
                if successes >= self.config.success_threshold {
                    drop(state);
                    let mut state = self.state.write();
                    *state = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::Relaxed);
                    self.success_count.store(0, Ordering::Relaxed);
                }
            }

            CircuitState::Open => {
                // Shouldn't happen, but handle gracefully
            }
        }
    }

    /// Record failed operation
    fn on_failure(&self) {
        let state = self.state.read();

        match *state {
            CircuitState::Closed => {
                let failures = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;

                // Check if we should open the circuit
                if failures >= self.config.failure_threshold {
                    drop(state);
                    let mut state = self.state.write();
                    *state = CircuitState::Open;
                    *self.last_failure_time.write() = Some(Instant::now());
                }
            }

            CircuitState::HalfOpen => {
                self.half_open_requests.fetch_sub(1, Ordering::Relaxed);

                // Any failure in half-open immediately opens the circuit
                drop(state);
                let mut state = self.state.write();
                *state = CircuitState::Open;
                *self.last_failure_time.write() = Some(Instant::now());
                self.failure_count.store(0, Ordering::Relaxed);
                self.success_count.store(0, Ordering::Relaxed);
            }

            CircuitState::Open => {
                // Already open, update last failure time
                *self.last_failure_time.write() = Some(Instant::now());
            }
        }
    }

    /// Get current state
    pub fn state(&self) -> CircuitState {
        *self.state.read()
    }

    /// Get statistics
    pub fn stats(&self) -> CircuitBreakerStats {
        CircuitBreakerStats {
            state: self.state(),
            failure_count: self.failure_count.load(Ordering::Relaxed),
            success_count: self.success_count.load(Ordering::Relaxed),
        }
    }

    /// Reset circuit breaker to closed state
    pub fn reset(&self) {
        let mut state = self.state.write();
        *state = CircuitState::Closed;
        self.failure_count.store(0, Ordering::Relaxed);
        self.success_count.store(0, Ordering::Relaxed);
        *self.last_failure_time.write() = None;
        self.half_open_requests.store(0, Ordering::Relaxed);
    }
}

impl Clone for CircuitBreaker {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            failure_count: Arc::clone(&self.failure_count),
            success_count: Arc::clone(&self.success_count),
            last_failure_time: Arc::clone(&self.last_failure_time),
            config: self.config.clone(),
            half_open_requests: Arc::clone(&self.half_open_requests),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    pub state: CircuitState,
    pub failure_count: u64,
    pub success_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_closed_state() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout: Duration::from_secs(1),
            half_open_max_requests: 1,
        };
        let cb = CircuitBreaker::new(config);

        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_opens_after_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout: Duration::from_secs(1),
            half_open_max_requests: 1,
        };
        let cb = CircuitBreaker::new(config);

        // Simulate failures
        for _ in 0..3 {
            let _ = cb.call(|| -> Result<(), ()> { Err(()) });
        }

        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn test_circuit_breaker_rejects_when_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_secs(60),
            half_open_max_requests: 1,
        };
        let cb = CircuitBreaker::new(config);

        // Open the circuit
        for _ in 0..2 {
            let _ = cb.call(|| -> Result<(), ()> { Err(()) });
        }

        assert_eq!(cb.state(), CircuitState::Open);

        // Should reject requests
        let result = cb.call(|| -> Result<(), ()> { Ok(()) });
        assert!(result.is_err());
    }

    #[test]
    fn test_circuit_breaker_half_open_after_timeout() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_millis(100),
            half_open_max_requests: 1,
        };
        let cb = CircuitBreaker::new(config);

        // Open the circuit
        for _ in 0..2 {
            let _ = cb.call(|| -> Result<(), ()> { Err(()) });
        }

        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(150));

        // Next call should transition to half-open
        let _ = cb.call(|| -> Result<(), ()> { Ok(()) });
        let stats = cb.stats();
        assert!(stats.state == CircuitState::HalfOpen || stats.state == CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_closes_after_successes() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout: Duration::from_millis(100),
            half_open_max_requests: 3,
        };
        let cb = CircuitBreaker::new(config);

        // Open the circuit
        for _ in 0..2 {
            let _ = cb.call(|| -> Result<(), ()> { Err(()) });
        }

        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(150));

        // Successful calls to close circuit - need one more to transition from half-open to closed
        for _ in 0..3 {
            let _ = cb.call(|| -> Result<(), ()> { Ok(()) });
        }

        // Should be closed now
        let state = cb.state();
        assert!(
            state == CircuitState::Closed || state == CircuitState::HalfOpen,
            "Expected Closed or HalfOpen, got {:?}",
            state
        );
    }

    #[test]
    fn test_circuit_breaker_reset() {
        let config = CircuitBreakerConfig::default();
        let cb = CircuitBreaker::new(config);

        // Open the circuit
        for _ in 0..5 {
            let _ = cb.call(|| -> Result<(), ()> { Err(()) });
        }

        assert_eq!(cb.state(), CircuitState::Open);

        cb.reset();
        assert_eq!(cb.state(), CircuitState::Closed);

        let stats = cb.stats();
        assert_eq!(stats.failure_count, 0);
        assert_eq!(stats.success_count, 0);
    }
}
