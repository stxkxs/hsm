use grpc_api::validation::*;
use proptest::prelude::*;

proptest! {
    #[test]
    fn fuzz_validate_key_id(key_id in prop::collection::vec(any::<u8>(), 0..512)) {
        // Should never panic
        let _ = validate_key_id(&key_id);
    }

    #[test]
    fn fuzz_validate_namespace(namespace in ".*") {
        // Should never panic
        let _ = validate_namespace(&namespace);
    }

    #[test]
    fn fuzz_validate_data_size(data in prop::collection::vec(any::<u8>(), 0..20_000_000)) {
        // Should never panic
        let _ = validate_data_size(&data, "fuzz");
    }

    #[test]
    fn fuzz_validate_batch_size(size in any::<usize>()) {
        // Should never panic
        let _ = validate_batch_size(size, "fuzz");
    }

    #[test]
    fn fuzz_validate_algorithm(algorithm in ".*") {
        // Should never panic
        let _ = validate_algorithm(&algorithm);
    }
}

#[cfg(test)]
mod quickcheck_tests {
    use super::*;
    use quickcheck::{quickcheck, TestResult};

    quickcheck! {
        fn qc_key_id_validation(key_id: Vec<u8>) -> TestResult {
            // Should never panic
            let result = validate_key_id(&key_id);

            // Empty key IDs should fail
            if key_id.is_empty() {
                return TestResult::from_bool(result.is_err());
            }

            // Too large key IDs should fail
            if key_id.len() > MAX_KEY_ID_SIZE {
                return TestResult::from_bool(result.is_err());
            }

            // Valid size should succeed
            TestResult::from_bool(result.is_ok())
        }

        fn qc_namespace_validation(namespace: String) -> TestResult {
            // Should never panic
            let result = validate_namespace(&namespace);

            // Empty namespaces should fail
            if namespace.is_empty() {
                return TestResult::from_bool(result.is_err());
            }

            // Too large namespaces should fail
            if namespace.len() > MAX_NAMESPACE_SIZE {
                return TestResult::from_bool(result.is_err());
            }

            // Invalid characters should fail
            let valid_chars = namespace.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_');
            if !valid_chars {
                return TestResult::from_bool(result.is_err());
            }

            // Valid namespace should succeed
            TestResult::from_bool(result.is_ok())
        }

        fn qc_data_size_validation(data: Vec<u8>) -> TestResult {
            // Should never panic
            let result = validate_data_size(&data, "test");

            // Empty data should fail
            if data.is_empty() {
                return TestResult::from_bool(result.is_err());
            }

            // Too large data should fail
            if data.len() > MAX_MESSAGE_SIZE {
                return TestResult::from_bool(result.is_err());
            }

            // Valid size should succeed
            TestResult::from_bool(result.is_ok())
        }

        fn qc_batch_size_validation(size: usize) -> TestResult {
            // Should never panic
            let result = validate_batch_size(size, "test");

            // Zero size should fail
            if size == 0 {
                return TestResult::from_bool(result.is_err());
            }

            // Too large should fail
            if size > MAX_BATCH_SIZE {
                return TestResult::from_bool(result.is_err());
            }

            // Valid size should succeed
            TestResult::from_bool(result.is_ok())
        }
    }
}

#[cfg(test)]
mod cache_fuzz {
    use super::*;
    use grpc_api::cache::*;
    use std::time::Duration;

    proptest! {
        #[test]
        fn fuzz_cache_operations(
            keys in prop::collection::vec("[a-z]{1,20}", 0..100),
            values in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..100), 0..100)
        ) {
            let cache = TtlCache::new(1000, Duration::from_secs(60));

            // Insert operations should never panic
            for (key, value) in keys.iter().zip(values.iter()) {
                cache.insert(key.clone(), value.clone());
            }

            // Get operations should never panic
            for key in keys.iter() {
                let _ = cache.get(key);
            }

            // Stats should never panic
            let _ = cache.stats();
        }

        #[test]
        fn fuzz_cache_invalidation(
            key in "[a-z]{1,20}",
            value in prop::collection::vec(any::<u8>(), 0..100)
        ) {
            let cache = TtlCache::new(100, Duration::from_secs(60));

            // Should never panic
            cache.insert(key.clone(), value.clone());
            cache.invalidate(&key);
            let _ = cache.get(&key);
        }
    }
}

#[cfg(test)]
mod circuit_breaker_fuzz {
    use super::*;
    use grpc_api::circuit_breaker::*;
    use std::time::Duration;

    proptest! {
        #[test]
        fn fuzz_circuit_breaker_calls(
            success_count in 0..100usize,
            failure_count in 0..100usize
        ) {
            let config = CircuitBreakerConfig {
                failure_threshold: 10,
                success_threshold: 5,
                timeout: Duration::from_millis(100),
                half_open_max_requests: 3,
            };
            let cb = CircuitBreaker::new(config);

            // Execute successful calls - should never panic
            for _ in 0..success_count {
                let _ = cb.call(|| -> Result<(), ()> { Ok(()) });
            }

            // Execute failed calls - should never panic
            for _ in 0..failure_count {
                let _ = cb.call(|| -> Result<(), ()> { Err(()) });
            }

            // Stats should never panic
            let _ = cb.stats();
        }

        #[test]
        fn fuzz_circuit_breaker_reset(iterations in 0..50usize) {
            let cb = CircuitBreaker::new(CircuitBreakerConfig::default());

            // Should never panic
            for _ in 0..iterations {
                let _ = cb.call(|| -> Result<(), ()> { Err(()) });
                cb.reset();
            }
        }
    }
}

#[cfg(test)]
mod error_fuzz {
    use super::*;
    use grpc_api::ApiError;
    use tonic::Status;

    proptest! {
        #[test]
        fn fuzz_error_conversion(msg in ".*") {
            // All error conversions should never panic
            let errors = vec![
                ApiError::KeyNotFound(msg.clone()),
                ApiError::InvalidKeyType(msg.clone()),
                ApiError::AuthenticationFailed(msg.clone()),
                ApiError::AuthorizationFailed(msg.clone()),
                ApiError::InvalidRequest(msg.clone()),
                ApiError::CryptoError(msg.clone()),
                ApiError::KeyManagerError(msg.clone()),
                ApiError::InternalError(msg.clone()),
                ApiError::DatabaseError(msg.clone()),
                ApiError::PolicyViolation(msg.clone()),
                ApiError::ResourceExhausted(msg.clone()),
            ];

            for error in errors {
                let status: Status = error.into();
                // Should never panic during conversion
                // Message may be empty for InvalidRequest with empty msg
                let _ = status.message();
            }
        }
    }
}

#[cfg(test)]
mod metadata_fuzz {
    use super::*;
    use std::collections::HashMap;

    proptest! {
        #[test]
        fn fuzz_validate_metadata(
            keys in prop::collection::vec(".*", 0..200),
            values in prop::collection::vec(".*", 0..200)
        ) {
            let mut metadata = HashMap::new();
            for (key, value) in keys.iter().zip(values.iter()) {
                metadata.insert(key.clone(), value.clone());
            }

            // Should never panic
            let _ = validate_metadata(&metadata);
        }
    }
}
