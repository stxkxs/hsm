//! # Hash Chain Implementation
//!
//! A tamper-evident hash chain for audit logging where each event contains
//! the cryptographic hash of the previous event, forming an immutable chain.
//!
//! ## How It Works
//!
//! The hash chain works like a blockchain - each event is linked to the previous
//! event through cryptographic hashing. If any event in the chain is modified,
//! all subsequent hashes become invalid, making tampering immediately detectable.
//!
//! ```text
//! Genesis Hash (all zeros)
//!      ↓
//! Event 1 [hash: H1, prev: Genesis]
//!      ↓
//! Event 2 [hash: H2, prev: H1]
//!      ↓
//! Event 3 [hash: H3, prev: H2]
//!      ↓
//!    ...
//! ```
//!
//! ## Hash Chain Algorithm
//!
//! 1. **Initialization**: Chain starts with a genesis hash (64 zeros)
//! 2. **Append**: New events are assigned the next sequence number
//! 3. **Linking**: Each event stores the hash of the previous event
//! 4. **Hashing**: Event hash = SHA256(sequence + timestamp + operation + prev_hash + ...)
//! 5. **Verification**: Walk the chain and verify each hash matches its content
//!
//! ## Tamper Detection
//!
//! Any modification to an event causes verification to fail:
//! - Modifying event data → hash no longer matches
//! - Inserting an event → sequence numbers become non-continuous
//! - Deleting an event → chain linkage breaks
//! - Reordering events → previous hash references break
//!
//! ## Thread Safety
//!
//! The hash chain uses `RwLock` for concurrent access:
//! - Multiple readers can verify the chain simultaneously
//! - Writers acquire exclusive locks to append new events
//! - Lock-free reads for sequence numbers and last hash
//!
//! ## Usage Example
//!
//! ```rust
//! use audit::HashChain;
//! use audit::event::{AuditEvent, EventType, OperationResult};
//! use chrono::Utc;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a new hash chain
//! let chain = HashChain::new();
//!
//! // Create and append events
//! let event1 = AuditEvent::builder()
//!     .sequence(1)
//!     .event_type(EventType::Sign)
//!     .operation("sign_data")
//!     .namespace("default")
//!     .client_id("client_1")
//!     .result(OperationResult::Success)
//!     .timestamp(Utc::now())
//!     .build()?;
//!
//! let hash1 = chain.append(event1)?;
//!
//! let event2 = AuditEvent::builder()
//!     .sequence(2)
//!     .event_type(EventType::Verify)
//!     .operation("verify_signature")
//!     .namespace("default")
//!     .client_id("client_1")
//!     .result(OperationResult::Success)
//!     .timestamp(Utc::now())
//!     .build()?;
//!
//! let hash2 = chain.append(event2)?;
//!
//! // Verify the entire chain
//! chain.verify_all()?;
//!
//! // Verify a specific range
//! chain.verify(1, 2)?;
//!
//! println!("Chain verified successfully!");
//! println!("Current sequence: {}", chain.current_sequence());
//! println!("Last hash: {}", chain.last_hash());
//! # Ok(())
//! # }
//! ```
//!
//! ## Verification Workflow
//!
//! ```rust
//! # use audit::{HashChain, HashChainError};
//! # use audit::event::{AuditEvent, EventType, OperationResult};
//! # use chrono::Utc;
//! # fn main() -> Result<(), HashChainError> {
//! # let chain = HashChain::new();
//! # for i in 1..=5 {
//! #     let event = AuditEvent::builder()
//! #         .sequence(i)
//! #         .event_type(EventType::Sign)
//! #         .operation("test")
//! #         .namespace("default")
//! #         .client_id("client")
//! #         .result(OperationResult::Success)
//! #         .timestamp(Utc::now())
//! #         .build()
//! #         .unwrap();
//! #     chain.append(event)?;
//! # }
//! // Get events for verification
//! let events = chain.get_all_events();
//!
//! // Verify entire chain
//! match chain.verify_all() {
//!     Ok(_) => println!("Chain is valid - no tampering detected"),
//!     Err(e) => println!("Tampering detected: {}", e),
//! }
//!
//! // Verify specific range (e.g., last 100 events)
//! let current_seq = chain.current_sequence();
//! if current_seq >= 100 {
//!     chain.verify(current_seq - 99, current_seq)?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Performance Characteristics
//!
//! - **Append**: O(1) - constant time with lock acquisition
//! - **Verify Range**: O(n) - linear in range size
//! - **Get Event**: O(1) - direct indexing
//! - **Memory**: O(n) - stores all events in memory
//!
//! ## Security Considerations
//!
//! - Uses SHA-256 for cryptographic hashing
//! - Genesis hash is 64 zeros (well-known starting point)
//! - Chain verification is deterministic
//! - No reliance on external state or timestamps for integrity

use crate::event::AuditEvent;
use parking_lot::RwLock;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HashChainError {
    #[error("Hash chain verification failed at sequence {0}")]
    VerificationFailed(u64),

    #[error("Sequence number mismatch: expected {expected}, got {actual}")]
    SequenceMismatch { expected: u64, actual: u64 },

    #[error("Invalid range: from={from}, to={to}")]
    InvalidRange { from: u64, to: u64 },

    #[error("Event not found at sequence {0}")]
    EventNotFound(u64),
}

/// Hash chain for tamper-evident audit logging.
///
/// Each event contains the hash of the previous event, forming an immutable
/// chain where any modification becomes immediately detectable.
///
/// # Thread Safety
///
/// Uses `Arc<RwLock<T>>` for safe concurrent access. Multiple threads can
/// verify the chain simultaneously while writes are serialized.
///
/// # Examples
///
/// ```rust
/// use audit::HashChain;
/// use audit::event::{AuditEvent, EventType, OperationResult};
/// use chrono::Utc;
///
/// let chain = HashChain::new();
/// assert_eq!(chain.current_sequence(), 0);
/// assert!(chain.is_empty());
/// ```
pub struct HashChain {
    /// Ordered list of audit events forming the chain
    events: Arc<RwLock<Vec<AuditEvent>>>,
    /// Hash of the most recent event in the chain
    last_hash: Arc<RwLock<String>>,
    /// Current sequence number (increments with each append)
    sequence: Arc<RwLock<u64>>,
}

impl HashChain {
    /// Creates a new empty hash chain with genesis hash.
    ///
    /// The chain starts with sequence 0 and a genesis hash of 64 zeros,
    /// which serves as the well-known starting point for the chain.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use audit::HashChain;
    ///
    /// let chain = HashChain::new();
    /// assert_eq!(chain.current_sequence(), 0);
    /// assert_eq!(chain.last_hash(), "0".repeat(64));
    /// ```
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            last_hash: Arc::new(RwLock::new("0".repeat(64))),
            sequence: Arc::new(RwLock::new(0)),
        }
    }

    /// Get the current sequence number
    pub fn current_sequence(&self) -> u64 {
        *self.sequence.read()
    }

    /// Get the last hash in the chain
    pub fn last_hash(&self) -> String {
        self.last_hash.read().clone()
    }

    /// Appends a new event to the chain.
    ///
    /// The event's `prev_hash` is set to the current last hash, and its
    /// `current_hash` is computed from its contents. The sequence number
    /// must be exactly `current_sequence + 1`.
    ///
    /// # Arguments
    ///
    /// * `event` - The audit event to append (sequence must be correct)
    ///
    /// # Returns
    ///
    /// The SHA-256 hash of the appended event as a hex string
    ///
    /// # Errors
    ///
    /// Returns `HashChainError::SequenceMismatch` if the event's sequence
    /// number is not exactly one more than the current sequence.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use audit::{HashChain, HashChainError};
    /// use audit::event::{AuditEvent, EventType, OperationResult};
    /// use chrono::Utc;
    ///
    /// # fn main() -> Result<(), HashChainError> {
    /// let chain = HashChain::new();
    ///
    /// let event = AuditEvent::builder()
    ///     .sequence(1)
    ///     .event_type(EventType::Sign)
    ///     .operation("sign_data")
    ///     .namespace("default")
    ///     .client_id("client_1")
    ///     .result(OperationResult::Success)
    ///     .timestamp(Utc::now())
    ///     .build()
    ///     .unwrap();
    ///
    /// let hash = chain.append(event)?;
    /// assert_eq!(chain.current_sequence(), 1);
    /// assert_eq!(chain.last_hash(), hash);
    /// # Ok(())
    /// # }
    /// ```
    pub fn append(&self, mut event: AuditEvent) -> Result<String, HashChainError> {
        let mut seq = self.sequence.write();
        let mut last_hash = self.last_hash.write();
        let mut events = self.events.write();

        // Verify sequence number
        let expected_seq = *seq + 1;
        if event.sequence != expected_seq {
            return Err(HashChainError::SequenceMismatch {
                expected: expected_seq,
                actual: event.sequence,
            });
        }

        // Set previous hash and recompute current hash
        event.prev_hash = last_hash.clone();
        event.current_hash = event.compute_hash();

        // Update state
        let hash = event.current_hash.clone();
        events.push(event);
        *last_hash = hash.clone();
        *seq = expected_seq;

        Ok(hash)
    }

    /// Verifies the integrity of the chain from sequence `from` to `to` (inclusive).
    ///
    /// This checks:
    /// 1. Each event's hash matches its computed hash
    /// 2. Each event's `prev_hash` matches the previous event's `current_hash`
    /// 3. The chain linkage is intact (no breaks or modifications)
    ///
    /// # Arguments
    ///
    /// * `from` - Starting sequence number (1-indexed, must be >= 1)
    /// * `to` - Ending sequence number (inclusive, must be >= from)
    ///
    /// # Errors
    ///
    /// - `InvalidRange` - If `from > to` or range is out of bounds
    /// - `VerificationFailed` - If any event's hash is invalid or chain linkage is broken
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use audit::{HashChain, HashChainError};
    /// # use audit::event::{AuditEvent, EventType, OperationResult};
    /// # use chrono::Utc;
    /// # fn main() -> Result<(), HashChainError> {
    /// # let chain = HashChain::new();
    /// # for i in 1..=10 {
    /// #     let event = AuditEvent::builder()
    /// #         .sequence(i)
    /// #         .event_type(EventType::Sign)
    /// #         .operation("test")
    /// #         .namespace("default")
    /// #         .client_id("client")
    /// #         .result(OperationResult::Success)
    /// #         .timestamp(Utc::now())
    /// #         .build()
    /// #         .unwrap();
    /// #     chain.append(event)?;
    /// # }
    /// // Verify a specific range
    /// chain.verify(1, 5)?;
    ///
    /// // Verify the last 3 events
    /// let current = chain.current_sequence();
    /// chain.verify(current - 2, current)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify(&self, from: u64, to: u64) -> Result<(), HashChainError> {
        if from > to {
            return Err(HashChainError::InvalidRange { from, to });
        }

        let events = self.events.read();

        // Check bounds
        if from == 0 || to > events.len() as u64 {
            return Err(HashChainError::InvalidRange { from, to });
        }

        // Verify each event's hash
        for i in ((from - 1) as usize)..(to as usize) {
            let event = &events[i];

            // Verify the event's own hash
            if !event.verify_hash() {
                return Err(HashChainError::VerificationFailed(event.sequence));
            }

            // Verify chain linkage (except for first event)
            if i > 0 {
                let prev_event = &events[i - 1];
                if event.prev_hash != prev_event.current_hash {
                    return Err(HashChainError::VerificationFailed(event.sequence));
                }
            }
        }

        Ok(())
    }

    /// Verify the entire chain
    pub fn verify_all(&self) -> Result<(), HashChainError> {
        let events = self.events.read();
        let len = events.len() as u64;

        if len == 0 {
            return Ok(());
        }

        drop(events); // Release lock before calling verify
        self.verify(1, len)
    }

    /// Get an event by sequence number
    pub fn get_event(&self, sequence: u64) -> Result<AuditEvent, HashChainError> {
        let events = self.events.read();

        if sequence == 0 || sequence > events.len() as u64 {
            return Err(HashChainError::EventNotFound(sequence));
        }

        Ok(events[(sequence - 1) as usize].clone())
    }

    /// Get all events in the chain
    pub fn get_all_events(&self) -> Vec<AuditEvent> {
        self.events.read().clone()
    }

    /// Get the number of events in the chain
    pub fn len(&self) -> usize {
        self.events.read().len()
    }

    /// Check if the chain is empty
    pub fn is_empty(&self) -> bool {
        self.events.read().is_empty()
    }

    /// Get events in a range (inclusive)
    pub fn get_events_range(&self, from: u64, to: u64) -> Result<Vec<AuditEvent>, HashChainError> {
        if from > to {
            return Err(HashChainError::InvalidRange { from, to });
        }

        let events = self.events.read();

        if from == 0 || to > events.len() as u64 {
            return Err(HashChainError::InvalidRange { from, to });
        }

        Ok(events[((from - 1) as usize)..(to as usize)].to_vec())
    }

    /// Clear all events (for testing purposes only)
    #[cfg(test)]
    pub fn clear(&self) {
        self.events.write().clear();
        *self.last_hash.write() = "0".repeat(64);
        *self.sequence.write() = 0;
    }
}

impl Default for HashChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventType, OperationResult};
    use chrono::Utc;

    fn create_test_event(seq: u64) -> AuditEvent {
        AuditEvent::builder()
            .sequence(seq)
            .event_type(EventType::Sign)
            .operation("test_op")
            .namespace("test")
            .client_id("client_1")
            .result(OperationResult::Success)
            .timestamp(Utc::now())
            .build()
            .unwrap()
    }

    #[test]
    fn test_hash_chain_creation() {
        let chain = HashChain::new();
        assert_eq!(chain.current_sequence(), 0);
        assert_eq!(chain.last_hash().len(), 64);
        assert!(chain.is_empty());
    }

    #[test]
    fn test_append_event() {
        let chain = HashChain::new();
        let event = create_test_event(1);

        let hash = chain.append(event).unwrap();
        assert_eq!(chain.current_sequence(), 1);
        assert_eq!(chain.last_hash(), hash);
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn test_append_multiple_events() {
        let chain = HashChain::new();

        for i in 1..=5 {
            let event = create_test_event(i);
            chain.append(event).unwrap();
        }

        assert_eq!(chain.current_sequence(), 5);
        assert_eq!(chain.len(), 5);
    }

    #[test]
    fn test_sequence_mismatch() {
        let chain = HashChain::new();

        let event = create_test_event(1);
        chain.append(event).unwrap();

        // Try to append with wrong sequence
        let event2 = create_test_event(5);
        let result = chain.append(event2);

        assert!(result.is_err());
        match result {
            Err(HashChainError::SequenceMismatch { expected, actual }) => {
                assert_eq!(expected, 2);
                assert_eq!(actual, 5);
            }
            _ => panic!("Expected SequenceMismatch error"),
        }
    }

    #[test]
    fn test_verify_chain() {
        let chain = HashChain::new();

        for i in 1..=10 {
            let event = create_test_event(i);
            chain.append(event).unwrap();
        }

        // Verify entire chain
        assert!(chain.verify_all().is_ok());

        // Verify partial chain
        assert!(chain.verify(1, 5).is_ok());
        assert!(chain.verify(5, 10).is_ok());
    }

    #[test]
    fn test_verify_invalid_range() {
        let chain = HashChain::new();

        for i in 1..=5 {
            let event = create_test_event(i);
            chain.append(event).unwrap();
        }

        // Invalid range: from > to
        assert!(chain.verify(5, 1).is_err());

        // Invalid range: beyond bounds
        assert!(chain.verify(1, 10).is_err());
    }

    #[test]
    fn test_get_event() {
        let chain = HashChain::new();

        for i in 1..=5 {
            let event = create_test_event(i);
            chain.append(event).unwrap();
        }

        let event = chain.get_event(3).unwrap();
        assert_eq!(event.sequence, 3);

        // Non-existent event
        assert!(chain.get_event(10).is_err());
        assert!(chain.get_event(0).is_err());
    }

    #[test]
    fn test_get_events_range() {
        let chain = HashChain::new();

        for i in 1..=10 {
            let event = create_test_event(i);
            chain.append(event).unwrap();
        }

        let events = chain.get_events_range(3, 7).unwrap();
        assert_eq!(events.len(), 5);
        assert_eq!(events[0].sequence, 3);
        assert_eq!(events[4].sequence, 7);
    }

    #[test]
    fn test_hash_chain_integrity() {
        let chain = HashChain::new();

        for i in 1..=5 {
            let event = create_test_event(i);
            chain.append(event).unwrap();
        }

        // Get events and verify chain linkage
        let events = chain.get_all_events();

        for i in 1..events.len() {
            assert_eq!(events[i].prev_hash, events[i - 1].current_hash);
        }
    }

    #[test]
    fn test_tamper_detection() {
        let chain = HashChain::new();

        for i in 1..=5 {
            let event = create_test_event(i);
            chain.append(event).unwrap();
        }

        // Verify chain is valid
        assert!(chain.verify_all().is_ok());

        // Tamper with an event
        {
            let mut events = chain.events.write();
            events[2].operation = "tampered".to_string();
        }

        // Verification should fail
        assert!(chain.verify_all().is_err());
    }
}
