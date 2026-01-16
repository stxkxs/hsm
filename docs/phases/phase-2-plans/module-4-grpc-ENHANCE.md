# Module 4: gRPC API Server - Phase 2 Enhancements

## Current Status
- ✅ 1,430 lines of code
- ✅ Compiles successfully
- ✅ Basic gRPC services
- ✅ Protocol buffer definitions

## Performance Enhancements

### 1. Connection Pooling (Priority: CRITICAL)
**Goal**: Support 10,000+ concurrent connections

**Tasks**:
- [ ] Implement connection pooling
- [ ] Optimize HTTP/2 settings (window size, max streams)
- [ ] Add connection keepalive tuning
- [ ] Profile connection overhead
- [ ] Benchmark concurrent connections

**Optimization**:
```rust
use tonic::transport::Server;

pub fn create_server() -> Result<Server> {
    Server::builder()
        // HTTP/2 settings
        .http2_keepalive_interval(Some(Duration::from_secs(30)))
        .http2_keepalive_timeout(Some(Duration::from_secs(10)))
        .http2_adaptive_window(true)
        // Increase initial window size for throughput
        .initial_connection_window_size(Some(1024 * 1024)) // 1MB
        .initial_stream_window_size(Some(1024 * 1024))     // 1MB
        // Concurrency settings
        .max_concurrent_streams(Some(1000))
        .tcp_nodelay(true)
        .build()
}
```

**Target**: 10,000+ concurrent connections with < 5% overhead

### 2. Request Batching (Priority: HIGH)
**Goal**: Reduce round trips for bulk operations

**Tasks**:
- [ ] Add batch endpoints for key operations
- [ ] Implement batch signing/verification
- [ ] Add batch encryption/decryption
- [ ] Optimize batch serialization
- [ ] Benchmark batch vs individual requests

**Batch API**:
```rust
service CryptoService {
    // Batch operations
    rpc BatchSign(BatchSignRequest) returns (BatchSignResponse);
    rpc BatchVerify(BatchVerifyRequest) returns (BatchVerifyResponse);
    rpc BatchEncrypt(BatchEncryptRequest) returns (BatchEncryptResponse);
    rpc BatchDecrypt(BatchDecryptRequest) returns (BatchDecryptResponse);
}

message BatchSignRequest {
    repeated SignRequest requests = 1;
    // Optional: parallel execution hint
    bool parallel = 2;
}

message BatchSignResponse {
    repeated SignResponse responses = 1;
}
```

**Expected speedup**: 5-10x for batch operations

### 3. Response Streaming (Priority: MEDIUM)
**Goal**: Efficient large result sets

**Tasks**:
- [ ] Add streaming for list operations
- [ ] Implement pagination with cursors
- [ ] Add streaming for large ciphertext/signatures
- [ ] Optimize stream backpressure
- [ ] Test streaming performance

**Streaming API**:
```rust
service KeyManagementService {
    // Stream keys instead of returning all at once
    rpc ListKeys(ListKeysRequest) returns (stream KeyInfo);

    // Stream audit logs
    rpc StreamAuditLogs(StreamAuditLogsRequest) returns (stream AuditEvent);
}
```

### 4. Protobuf Optimization (Priority: HIGH)
**Goal**: Minimize serialization overhead

**Tasks**:
- [ ] Use bytes instead of string for binary data
- [ ] Add arena allocation for repeated fields
- [ ] Optimize message sizes
- [ ] Profile serialization performance
- [ ] Benchmark different protobuf options

**Optimized proto**:
```protobuf
message SignRequest {
    bytes key_id = 1;        // Use bytes for binary IDs
    bytes data = 2;          // Use bytes for data
    SignAlgorithm algorithm = 3;

    // Avoid nested messages in hot path
    // Use flat structure when possible
}
```

### 5. Request Caching (Priority: MEDIUM)
**Goal**: Cache idempotent operations

**Tasks**:
- [ ] Implement response caching for read operations
- [ ] Add cache invalidation on writes
- [ ] Use LRU cache with TTL
- [ ] Profile cache hit rates
- [ ] Benchmark cached vs uncached

## Security Enhancements

### 1. Input Validation (Priority: CRITICAL)
**Goal**: Validate all inputs at API boundary

**Tasks**:
- [ ] Add size limits on all request fields
- [ ] Validate key IDs format
- [ ] Check namespace format
- [ ] Add fuzz testing for all endpoints
- [ ] Return specific error messages

**Validation**:
```rust
impl CryptoServiceImpl {
    fn validate_sign_request(&self, req: &SignRequest) -> Result<()> {
        // Validate key ID
        if req.key_id.is_empty() {
            return Err(Status::invalid_argument("key_id is required"));
        }
        if req.key_id.len() > MAX_KEY_ID_SIZE {
            return Err(Status::invalid_argument("key_id too large"));
        }

        // Validate data size
        if req.data.len() > MAX_MESSAGE_SIZE {
            return Err(Status::invalid_argument(
                format!("data too large: {} > {}", req.data.len(), MAX_MESSAGE_SIZE)
            ));
        }

        // Validate namespace
        if !is_valid_namespace(&req.namespace) {
            return Err(Status::invalid_argument("invalid namespace format"));
        }

        Ok(())
    }
}
```

### 2. Request Size Limits (Priority: HIGH)
**Goal**: Prevent DoS via large requests

**Tasks**:
- [ ] Add max message size limits
- [ ] Limit batch operation sizes
- [ ] Add streaming backpressure
- [ ] Test with oversized requests
- [ ] Document size limits

**Configuration**:
```rust
Server::builder()
    .max_frame_size(Some(1024 * 1024))  // 1MB max frame
    .max_decoding_message_size(8 * 1024 * 1024)  // 8MB max message
    .max_encoding_message_size(8 * 1024 * 1024)
```

### 3. Error Handling (Priority: HIGH)
**Goal**: Never leak sensitive information

**Tasks**:
- [ ] Audit all error messages
- [ ] Remove sensitive data from errors
- [ ] Use opaque errors at API boundary
- [ ] Log detailed errors internally
- [ ] Add error handling tests

**Safe error handling**:
```rust
impl From<CryptoError> for Status {
    fn from(err: CryptoError) -> Status {
        // Log full error internally
        error!("Crypto operation failed: {:?}", err);

        // Return opaque error to client
        match err {
            CryptoError::KeyNotFound(_) => {
                Status::not_found("Key not found")
            }
            CryptoError::SigningFailed(_) => {
                // Don't leak key details!
                Status::internal("Signing operation failed")
            }
            CryptoError::InvalidKeySize(_) => {
                Status::invalid_argument("Invalid key size")
            }
            _ => Status::internal("Operation failed")
        }
    }
}
```

### 4. mTLS Integration (Priority: CRITICAL)
**Goal**: Enforce mTLS for all connections

**Tasks**:
- [ ] Configure TLS with client cert requirement
- [ ] Extract client identity from cert
- [ ] Pass identity to auth module
- [ ] Add connection security tests
- [ ] Document TLS configuration

**mTLS setup**:
```rust
use tonic::transport::{Server, ServerTlsConfig, Certificate, Identity};

pub fn create_mtls_server(config: &TlsConfig) -> Result<Server> {
    let cert = tokio::fs::read(&config.cert_path).await?;
    let key = tokio::fs::read(&config.key_path).await?;
    let server_identity = Identity::from_pem(cert, key);

    let client_ca_cert = tokio::fs::read(&config.client_ca_path).await?;
    let client_ca = Certificate::from_pem(client_ca_cert);

    let tls_config = ServerTlsConfig::new()
        .identity(server_identity)
        .client_ca_root(client_ca);

    Server::builder()
        .tls_config(tls_config)?
        .build()
}
```

### 5. Request Tracing (Priority: MEDIUM)
**Goal**: Full request observability

**Tasks**:
- [ ] Add request IDs to all requests
- [ ] Implement distributed tracing
- [ ] Log request/response metadata
- [ ] Integrate with metrics module
- [ ] Add tracing to audit logs

## Reliability Enhancements

### 1. Health Checks (Priority: HIGH)
**Goal**: Proper health/readiness endpoints

**Tasks**:
- [ ] Implement gRPC health checking protocol
- [ ] Add liveness probe
- [ ] Add readiness probe
- [ ] Check backend dependencies
- [ ] Test health check reliability

**Health service**:
```rust
use tonic_health::server::HealthReporter;

#[tonic::async_trait]
impl Health for HealthService {
    async fn check(&self, req: HealthCheckRequest) -> Result<HealthCheckResponse> {
        let status = match req.service.as_str() {
            "" => self.check_overall_health().await?,
            "crypto" => self.check_crypto_engine().await?,
            "storage" => self.check_storage().await?,
            _ => ServingStatus::Unknown,
        };

        Ok(HealthCheckResponse {
            status: status as i32,
        })
    }
}
```

### 2. Graceful Shutdown (Priority: HIGH)
**Goal**: Clean server shutdown

**Tasks**:
- [ ] Implement graceful shutdown
- [ ] Drain existing connections
- [ ] Add shutdown timeout
- [ ] Test shutdown behavior
- [ ] Document shutdown procedure

**Graceful shutdown**:
```rust
pub async fn run_server(server: Server, shutdown_signal: impl Future<Output = ()>) -> Result<()> {
    server
        .serve_with_shutdown(addr, async {
            shutdown_signal.await;
            info!("Shutdown signal received, draining connections...");
        })
        .await?;

    info!("Server shutdown complete");
    Ok(())
}
```

### 3. Circuit Breakers (Priority: MEDIUM)
**Goal**: Prevent cascading failures

**Tasks**:
- [ ] Add circuit breakers for backend calls
- [ ] Implement retry logic with backoff
- [ ] Add timeout configuration
- [ ] Test failure scenarios
- [ ] Add circuit breaker metrics

### 4. Request Deadlines (Priority: MEDIUM)
**Goal**: Prevent hung requests

**Tasks**:
- [ ] Enforce request deadlines
- [ ] Add timeout configuration per operation
- [ ] Test timeout behavior
- [ ] Add deadline metrics
- [ ] Document timeout settings

## Testing Enhancements

### 1. Load Testing (Priority: HIGH)
**Goal**: Verify performance targets

**Tasks**:
- [ ] Create load test suite with ghz
- [ ] Test 10,000+ concurrent connections
- [ ] Benchmark throughput (requests/sec)
- [ ] Measure latency distribution
- [ ] Test under sustained load

**Load test example**:
```bash
# Benchmark sign operations
ghz --insecure \
  --proto crypto.proto \
  --call hsm.CryptoService/Sign \
  -d '{"key_id":"test","data":"aGVsbG8="}' \
  -c 100 \
  -n 10000 \
  localhost:50051
```

### 2. Fuzz Testing (Priority: HIGH)
**Goal**: Find edge cases and crashes

**Tasks**:
- [ ] Add fuzz tests for all endpoints
- [ ] Test with malformed protobufs
- [ ] Test with oversized inputs
- [ ] Test with invalid UTF-8
- [ ] Run fuzzing for 1M+ iterations

### 3. Integration Tests (Priority: HIGH)
**Goal**: End-to-end API tests

**Tasks**:
- [ ] Test all API endpoints
- [ ] Test error cases
- [ ] Test streaming operations
- [ ] Test batch operations
- [ ] Test mTLS authentication

**Integration test**:
```rust
#[tokio::test]
async fn test_sign_verify_flow() -> Result<()> {
    let client = create_test_client().await?;

    // Generate key
    let gen_resp = client.generate_key(GenerateKeyRequest {
        key_type: KeyType::Ed25519 as i32,
        namespace: "test".to_string(),
    }).await?;

    let key_id = gen_resp.into_inner().key_id;

    // Sign data
    let sign_resp = client.sign(SignRequest {
        key_id: key_id.clone(),
        data: b"hello world".to_vec(),
        algorithm: SignAlgorithm::Ed25519 as i32,
    }).await?;

    let signature = sign_resp.into_inner().signature;

    // Verify signature
    let verify_resp = client.verify(VerifyRequest {
        key_id,
        data: b"hello world".to_vec(),
        signature,
        algorithm: SignAlgorithm::Ed25519 as i32,
    }).await?;

    assert!(verify_resp.into_inner().valid);
    Ok(())
}
```

## Success Metrics

**Performance**:
- ✅ Concurrent connections: > 10,000
- ✅ Throughput: > 5,000 requests/sec
- ✅ Latency p50: < 10ms
- ✅ Latency p99: < 100ms
- ✅ Batch speedup: 5-10x

**Security**:
- ✅ All inputs validated
- ✅ mTLS enforced on all connections
- ✅ No sensitive data in errors
- ✅ Fuzz testing passes 1M iterations

**Reliability**:
- ✅ Health checks working
- ✅ Graceful shutdown < 30s
- ✅ Circuit breakers prevent cascading failures
- ✅ > 90% test coverage

## Claude Agent Instructions

1. Read this enhancement plan
2. Run existing tests to verify baseline
3. Implement connection pooling and HTTP/2 optimization
4. Add comprehensive input validation
5. Implement batch operations
6. Add health checks and graceful shutdown
7. Verify performance targets with load tests
8. Run fuzz tests and fix any issues
9. Achieve all success metrics
