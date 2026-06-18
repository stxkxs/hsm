use hsm_grpc_api::*;

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.bind_address, "0.0.0.0:50051");
        assert!(config.cache.enabled);
        assert!(config.circuit_breaker.enabled);
    }

    #[test]
    fn test_http2_config_performance_settings() {
        let config = Http2Config::default();

        // Verify performance optimizations
        assert_eq!(config.initial_connection_window_size, 1024 * 1024); // 1MB
        assert_eq!(config.initial_stream_window_size, 1024 * 1024); // 1MB
        assert_eq!(config.max_concurrent_streams, 1000);
        assert!(config.adaptive_window);
        assert!(config.tcp_nodelay);

        // Verify security limits
        assert_eq!(config.max_decoding_message_size, 8 * 1024 * 1024); // 8MB
        assert_eq!(config.max_encoding_message_size, 8 * 1024 * 1024); // 8MB
    }

    #[test]
    fn test_limits_config() {
        let config = LimitsConfig::default();
        assert_eq!(config.max_connections, 10000);
        assert_eq!(config.max_batch_size, 1000);
        assert!(config.request_timeout_secs > 0);
    }
}

#[cfg(test)]
mod validation_tests {

    use hsm_grpc_api::validation::*;

    #[test]
    fn test_key_id_validation() {
        // Valid key IDs
        assert!(validate_key_id(b"test-key-123").is_ok());
        assert!(validate_key_id(&[0u8; 256]).is_ok());

        // Invalid key IDs
        assert!(validate_key_id(b"").is_err());
        assert!(validate_key_id(&vec![0u8; MAX_KEY_ID_SIZE + 1]).is_err());
    }

    #[test]
    fn test_namespace_validation() {
        // Valid namespaces
        assert!(validate_namespace("test").is_ok());
        assert!(validate_namespace("test-namespace").is_ok());
        assert!(validate_namespace("test_namespace_123").is_ok());

        // Invalid namespaces
        assert!(validate_namespace("").is_err());
        assert!(validate_namespace("test@namespace").is_err());
        assert!(validate_namespace("test namespace").is_err());
        assert!(validate_namespace(&"x".repeat(MAX_NAMESPACE_SIZE + 1)).is_err());
    }

    #[test]
    fn test_data_size_validation() {
        // Valid data
        assert!(validate_data_size(&vec![0u8; 1024], "test").is_ok());
        assert!(validate_data_size(&vec![0u8; MAX_MESSAGE_SIZE], "test").is_ok());

        // Invalid data
        assert!(validate_data_size(&[], "test").is_err());
        assert!(validate_data_size(&vec![0u8; MAX_MESSAGE_SIZE + 1], "test").is_err());
    }

    #[test]
    fn test_batch_size_validation() {
        // Valid batch sizes
        assert!(validate_batch_size(1, "test").is_ok());
        assert!(validate_batch_size(MAX_BATCH_SIZE, "test").is_ok());

        // Invalid batch sizes
        assert!(validate_batch_size(0, "test").is_err());
        assert!(validate_batch_size(MAX_BATCH_SIZE + 1, "test").is_err());
    }

    #[test]
    fn test_metadata_validation() {
        use std::collections::HashMap;

        // Valid metadata
        let mut metadata = HashMap::new();
        metadata.insert("key1".to_string(), "value1".to_string());
        assert!(validate_metadata(&metadata).is_ok());

        // Too many entries
        let mut large_metadata = HashMap::new();
        for i in 0..=MAX_METADATA_ENTRIES {
            large_metadata.insert(format!("key{}", i), "value".to_string());
        }
        assert!(validate_metadata(&large_metadata).is_err());

        // Key too large
        let mut invalid_metadata = HashMap::new();
        invalid_metadata.insert("k".repeat(MAX_METADATA_KEY_SIZE + 1), "value".to_string());
        assert!(validate_metadata(&invalid_metadata).is_err());

        // Value too large
        let mut invalid_metadata = HashMap::new();
        invalid_metadata.insert("key".to_string(), "v".repeat(MAX_METADATA_VALUE_SIZE + 1));
        assert!(validate_metadata(&invalid_metadata).is_err());
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_response_cache_creation() {
        let cache = ResponseCache::new();
        let stats = cache.stats();

        assert_eq!(stats.get_key.size, 0);
        assert_eq!(stats.verify.size, 0);
    }

    #[test]
    fn test_cache_invalidation() {
        let cache = ResponseCache::new();

        let key_id = b"test-key".to_vec();
        let namespace = "test";

        let cache_key = CacheKey::GetKey {
            key_id: key_id.clone(),
            namespace: namespace.to_string(),
        };

        cache.get_key_cache.insert(cache_key.clone(), vec![1, 2, 3]);
        assert!(cache.get_key_cache.get(&cache_key).is_some());

        cache.invalidate_key(&key_id, namespace);
        assert!(cache.get_key_cache.get(&cache_key).is_none());
    }

    #[test]
    fn test_cache_cleanup() {
        let cache = ResponseCache::new();

        let cache_key = CacheKey::GetKey {
            key_id: b"test".to_vec(),
            namespace: "test".to_string(),
        };

        cache.get_key_cache.insert_with_ttl(
            cache_key.clone(),
            vec![1, 2, 3],
            Duration::from_millis(10),
        );

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        cache.cleanup_expired();
        assert!(cache.get_key_cache.get(&cache_key).is_none());
    }
}

#[cfg(test)]
mod circuit_breaker_tests {
    use super::*;
    use std::time::Duration;

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
    fn test_circuit_breaker_opens_on_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout: Duration::from_secs(60),
            half_open_max_requests: 1,
        };
        let cb = CircuitBreaker::new(config);

        // Trigger failures
        for _ in 0..3 {
            let _ = cb.call(|| -> std::result::Result<(), ()> { Err(()) });
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
            let _ = cb.call(|| -> std::result::Result<(), ()> { Err(()) });
        }

        // Should reject new requests
        let result = cb.call(|| -> std::result::Result<(), ()> { Ok(()) });
        assert!(result.is_err());
    }

    #[test]
    fn test_circuit_breaker_stats() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
        let stats = cb.stats();

        assert_eq!(stats.state, CircuitState::Closed);
        assert_eq!(stats.failure_count, 0);
        assert_eq!(stats.success_count, 0);
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;
    use tonic::Status;

    #[test]
    fn test_error_conversion_sanitizes_messages() {
        // Key not found should not leak key ID
        let error = ApiError::KeyNotFound("secret-key-123".to_string());
        let status: Status = error.into();
        assert_eq!(status.message(), "Key not found");
        assert!(!status.message().contains("secret-key-123"));

        // Crypto errors should not leak implementation details
        let error = ApiError::CryptoError("RSA private key details".to_string());
        let status: Status = error.into();
        assert_eq!(status.message(), "Cryptographic operation failed");
        assert!(!status.message().contains("RSA"));

        // Database errors should be opaque
        let error = ApiError::DatabaseError("SELECT * FROM keys WHERE id = 123".to_string());
        let status: Status = error.into();
        assert_eq!(status.message(), "Service temporarily unavailable");
        assert!(!status.message().contains("SELECT"));
    }

    #[test]
    fn test_error_codes() {
        use tonic::Code;

        let error = ApiError::KeyNotFound("test".to_string());
        let status: Status = error.into();
        assert_eq!(status.code(), Code::NotFound);

        let error = ApiError::AuthenticationFailed("test".to_string());
        let status: Status = error.into();
        assert_eq!(status.code(), Code::Unauthenticated);

        let error = ApiError::AuthorizationFailed("test".to_string());
        let status: Status = error.into();
        assert_eq!(status.code(), Code::PermissionDenied);

        let error = ApiError::RateLimitExceeded;
        let status: Status = error.into();
        assert_eq!(status.code(), Code::ResourceExhausted);
    }
}

#[cfg(test)]
mod proto_tests {
    use super::*;

    #[test]
    fn test_proto_batch_sign_request() {
        let req = BatchSignRequest {
            requests: vec![],
            parallel: true,
        };
        assert!(req.parallel);
    }

    #[test]
    fn test_proto_batch_verify_request() {
        let req = BatchVerifyRequest {
            requests: vec![],
            parallel: false,
        };
        assert!(!req.parallel);
    }

    #[test]
    fn test_proto_batch_encrypt_request() {
        let req = BatchEncryptRequest {
            requests: vec![],
            parallel: true,
        };
        assert!(req.parallel);
    }

    #[test]
    fn test_proto_batch_decrypt_request() {
        let req = BatchDecryptRequest {
            requests: vec![],
            parallel: false,
        };
        assert!(!req.parallel);
    }
}
