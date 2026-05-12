use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Rate limiter state for a session
#[derive(Debug)]
pub struct RateLimiterState {
    /// Operations in current window
    operations: AtomicU64,
    /// Window start time
    window_start: RwLock<DateTime<Utc>>,
    /// Operations per second limit
    limit: u32,
}

impl RateLimiterState {
    /// Create a new rate limiter
    pub fn new(limit: u32) -> Self {
        Self {
            operations: AtomicU64::new(0),
            window_start: RwLock::new(Utc::now()),
            limit,
        }
    }

    /// Check and increment rate limiter
    /// Returns Ok(()) if allowed, Err if rate limited
    pub fn check_and_increment(&self) -> std::result::Result<(), &'static str> {
        let now = Utc::now();
        let mut window_start = self.window_start.write();

        // Reset window if more than 1 second has passed
        if now.signed_duration_since(*window_start).num_seconds() >= 1 {
            *window_start = now;
            self.operations.store(1, Ordering::SeqCst);
            return Ok(());
        }

        // Check if within limit
        let current = self.operations.fetch_add(1, Ordering::SeqCst);
        if current >= self.limit as u64 {
            self.operations.fetch_sub(1, Ordering::SeqCst);
            return Err("Rate limit exceeded");
        }

        Ok(())
    }

    /// Get current operation count in window
    pub fn current_count(&self) -> u64 {
        self.operations.load(Ordering::SeqCst)
    }
}
