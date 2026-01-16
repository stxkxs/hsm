# Module 4: gRPC API Server - Implementation Plan

## Agent Mission
Build a high-performance gRPC API server that exposes all HSM functionality with proper request validation, error handling, and integration with auth, key management, and crypto modules.

## Critical Success Factors
1. API must handle 1000+ requests/second
2. All requests must be authenticated and authorized
3. Proper error handling with meaningful status codes
4. Request/response validation
5. Concurrent request handling
6. Graceful shutdown

## File Structure
```
crates/grpc-api/
├── Cargo.toml
├── build.rs                   # Protobuf compilation
├── proto/
│   └── hsm.proto              # API definitions
├── src/
│   ├── lib.rs
│   ├── server.rs              # gRPC server setup
│   ├── handlers/
│   │   ├── mod.rs
│   │   ├── key_management.rs  # Key CRUD operations
│   │   ├── crypto_ops.rs      # Sign/encrypt/decrypt
│   │   ├── audit.rs           # Audit log access
│   │   └── health.rs          # Health checks
│   ├── middleware/
│   │   ├── auth.rs            # Auth middleware
│   │   ├── logging.rs         # Request logging
│   │   └── metrics.rs         # Metrics collection
│   └── error.rs               # Error mapping
└── tests/
    └── integration_tests.rs
```

## Proto Definition
```protobuf
// proto/hsm.proto
syntax = "proto3";

package hsm.v1;

service HSM {
  rpc GenerateKey(GenerateKeyRequest) returns (GenerateKeyResponse);
  rpc Sign(SignRequest) returns (SignResponse);
  rpc Verify(VerifyRequest) returns (VerifyResponse);
  rpc Encrypt(EncryptRequest) returns (EncryptResponse);
  rpc Decrypt(DecryptRequest) returns (DecryptResponse);
  // ... more operations
}

message GenerateKeyRequest {
  string namespace = 1;
  KeyType key_type = 2;
  KeyUsagePolicy policy = 3;
}

message GenerateKeyResponse {
  string key_id = 1;
  bytes public_key = 2;
}
```

## Dependencies
```toml
[dependencies]
tonic = "0.11"
prost = "0.12"
tokio = { version = "1.35", features = ["full"] }
hsm-crypto-engine = { path = "../crypto-engine" }
hsm-key-manager = { path = "../key-manager" }
hsm-auth = { path = "../auth" }

[build-dependencies]
tonic-build = "0.11"
```

## Timeline
- Day 1: Protobuf definitions + code generation
- Day 2: Server setup + middleware
- Day 3: Handler implementation
- Day 4: Testing + load testing
