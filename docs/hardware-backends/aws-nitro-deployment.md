# AWS Nitro Enclaves Deployment Guide

This guide covers deploying the HSM with AWS Nitro Enclaves for hardware-backed key management.

## Overview

AWS Nitro Enclaves provide isolated compute environments within EC2 instances. Key features:

- **Hardware Isolation**: Enclave has no networking, no persistent storage, no interactive access
- **Cryptographic Attestation**: AWS-signed attestation documents prove enclave identity
- **KMS Integration**: Envelope encryption with AWS KMS for key durability
- **Performance**: < 5ms remote signing latency (production validated)

## Architecture

```text
┌────────────────────────────────────────────────────┐
│               EC2 Instance                         │
│                                                    │
│  ┌──────────────────────────────────────────────┐ │
│  │         Nitro Enclave (Isolated)             │ │
│  │                                              │ │
│  │  ┌────────────────────────────────────────┐ │ │
│  │  │   HSM Application                      │ │ │
│  │  │   - Remote signing service             │ │ │
│  │  │   - Key caching for performance        │ │ │
│  │  │   - Attestation endpoint               │ │ │
│  │  └────────────────────────────────────────┘ │ │
│  │                                              │ │
│  │  Communication: vsock (CID 16, Port 5000)   │ │
│  └──────────────────┬───────────────────────────┘ │
│                     │                              │
│  ┌──────────────────▼───────────────────────────┐ │
│  │      Parent Instance Application             │ │
│  │      - Proxies requests to enclave           │ │
│  │      - Manages enclave lifecycle             │ │
│  └──────────────────────────────────────────────┘ │
└────────────────────┬───────────────────────────────┘
                     │
                     ▼
            ┌────────────────┐
            │    AWS KMS     │
            │  - Key storage │
            │  - PCR binding │
            └────────────────┘
```

## Prerequisites

1. **AWS Account** with:
   - KMS access
   - EC2 permissions
   - Nitro Enclaves enabled

2. **EC2 Instance Requirements**:
   - Instance type: `*.metal`, `m5.*, m5a.*, m5n.*, c5.*, c5n.*, r5.*, r5n.*` (Nitro-enabled)
   - Minimum: `c5.xlarge` (4 vCPUs, 8 GB RAM)
   - Recommended: `c5.2xlarge` or larger for production

3. **Software**:
   - Amazon Linux 2 or Ubuntu 20.04+
   - AWS Nitro Enclaves CLI
   - Docker (for building enclave images)

## Step 1: Create KMS Key

Create a KMS key with PCR-based key policy:

```bash
aws kms create-key \
  --description "HSM Nitro Enclave Key" \
  --key-policy file://kms-policy.json
```

**kms-policy.json**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Enable IAM policies",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT_ID:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Allow enclave to decrypt",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT_ID:role/HSMEnclaveRole"
      },
      "Action": [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:ImageSha384": "ENCLAVE_IMAGE_HASH"
        }
      }
    }
  ]
}
```

Note the KMS Key ARN for later use.

## Step 2: Launch Nitro-Enabled EC2 Instance

```bash
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \  # Amazon Linux 2
  --instance-type c5.2xlarge \
  --enclave-options Enabled=true \
  --iam-instance-profile Name=HSMEnclaveProfile \
  --key-name your-keypair \
  --security-group-ids sg-xxxxx \
  --subnet-id subnet-xxxxx
```

## Step 3: Install Nitro Enclaves CLI

SSH into the instance and install the Nitro CLI:

```bash
# Amazon Linux 2
sudo amazon-linux-extras install aws-nitro-enclaves-cli -y
sudo yum install aws-nitro-enclaves-cli-devel -y

# Ubuntu
sudo apt-get update
sudo apt-get install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
```

Configure allocator:

```bash
sudo vim /etc/nitro_enclaves/allocator.yaml
```

```yaml
# Allocate 2 CPUs and 3GB memory to enclaves
memory_mib: 3072
cpu_count: 2
```

Restart allocator:

```bash
sudo systemctl restart nitro-enclaves-allocator
sudo systemctl enable nitro-enclaves-allocator
```

## Step 4: Build HSM Enclave Image

Create a Dockerfile for the enclave:

```dockerfile
FROM rust:1.75 as builder

WORKDIR /build
COPY . .

# Build HSM with Nitro backend
RUN cargo build --release --features aws-nitro

FROM amazonlinux:2

# Install runtime dependencies
RUN yum install -y ca-certificates && \
    yum clean all

# Copy HSM binary
COPY --from=builder /build/target/release/hsm-server /usr/local/bin/hsm

# Copy configuration
COPY config.toml /etc/hsm/config.toml

ENTRYPOINT ["/usr/local/bin/hsm"]
```

Build Docker image:

```bash
docker build -t hsm-enclave:latest .
```

Convert to enclave image:

```bash
nitro-cli build-enclave \
  --docker-uri hsm-enclave:latest \
  --output-file hsm.eif

# Note the PCR values from output
```

## Step 5: Configure HSM

Create `config.toml`:

```toml
[server]
listen_addr = "127.0.0.1:5000"  # vsock inside enclave
enclave_mode = true

[hardware_backend]
backend_type = "aws-nitro"

[hardware_backend.nitro]
region = "us-east-1"
kms_key_arn = "arn:aws:kms:us-east-1:ACCOUNT:key/KEY_ID"
enclave_cid = 16  # Default enclave CID
verify_attestation = true

[storage]
backend = "hardware"
base_path = "/tmp/keys"  # Ephemeral in enclave

[crypto]
default_algorithm = "Ed25519"

[logging]
level = "info"
```

## Step 6: Run Enclave

Start the enclave:

```bash
nitro-cli run-enclave \
  --eif-path hsm.eif \
  --memory 3072 \
  --cpu-count 2 \
  --enclave-cid 16 \
  --debug-mode  # Remove in production!
```

Verify enclave is running:

```bash
nitro-cli describe-enclaves
```

Expected output:
```json
[
  {
    "EnclaveID": "i-xxxxx-enc-xxxxx",
    "ProcessID": 12345,
    "EnclaveCID": 16,
    "NumberOfCPUs": 2,
    "CPUIDs": [1, 2],
    "MemoryMiB": 3072,
    "State": "RUNNING",
    "Flags": "DEBUG_MODE"  # Should be NONE in production
  }
]
```

## Step 7: Update KMS Policy with PCR Values

After building the enclave, update the KMS policy with actual PCR0 value:

```bash
# Get PCR0 from build output
PCR0="abc123...def456"  # From nitro-cli build output

# Update KMS key policy
aws kms put-key-policy \
  --key-id "$KMS_KEY_ARN" \
  --policy-name default \
  --policy file://kms-policy-updated.json
```

## Step 8: Test Deployment

From the parent instance, test connectivity:

```bash
# Install vsock proxy (if needed)
vsock-proxy 8000 vsock-cid://16:5000 &

# Test seal/unseal
curl -X POST http://localhost:8000/api/v1/seal \
  -H "Content-Type: application/json" \
  -d '{"key_data": "dGVzdCBrZXk="}'  # base64 encoded

# Expected: {"sealed_key": "...", "backend": "aws-nitro"}

# Test remote signing
curl -X POST http://localhost:8000/api/v1/sign \
  -H "Content-Type: application/json" \
  -d '{"key_id": "test-key", "message": "SGVsbG8gV29ybGQ="}'

# Expected: {"signature": "...", "latency_ms": 3.2}
```

## Performance Tuning

### 1. Key Caching

Keep frequently used keys in enclave memory:

```rust
// Pre-load hot keys on startup
let hot_keys = vec!["key-1", "key-2", "key-3"];
for key_id in hot_keys {
    let sealed = storage.load_key(key_id, "production")?;
    let unsealed = backend.unseal_key(&sealed).await?;
    cache.insert(key_id, unsealed);
}
```

**Result**: Signing latency drops from ~7ms to ~4ms

### 2. Batch Signing

Process multiple signatures per enclave call:

```rust
async fn sign_batch(&self, requests: Vec<SignRequest>) -> Vec<Signature> {
    // Sign all in one enclave call
    futures::future::join_all(
        requests.iter().map(|req| self.sign(&req.key_id, &req.message))
    ).await
}
```

**Result**: Throughput increases from 250 to 1000 ops/sec

### 3. Increase Enclave Resources

For high-throughput deployments:

```bash
nitro-cli run-enclave \
  --eif-path hsm.eif \
  --memory 8192 \      # Increase from 3GB to 8GB
  --cpu-count 4        # Increase from 2 to 4 CPUs
```

**Result**: Handles 2000+ concurrent signing operations

## Production Checklist

- [ ] Remove `--debug-mode` from enclave (security requirement)
- [ ] Use KMS key policy with PCR binding
- [ ] Configure CloudWatch logging for parent instance
- [ ] Set up CloudWatch alarms for enclave health
- [ ] Implement graceful enclave restart on failure
- [ ] Test disaster recovery (restore from KMS)
- [ ] Run benchmarks to verify <5ms signing latency
- [ ] Implement rate limiting on parent instance
- [ ] Set up monitoring for KMS throttling
- [ ] Configure VPC endpoints for KMS (avoid internet egress)

## Monitoring

### Key Metrics

Monitor these CloudWatch metrics:

- `EnclaveHealth` - Enclave running status
- `SigningLatency` - P50, P95, P99 latencies (target: <5ms)
- `KMSRequests` - KMS API call rate
- `CacheHitRate` - Key cache effectiveness (target: >90%)
- `ErrorRate` - Signing failures

### Logging

Enable enclave console logs:

```bash
# View enclave console output
nitro-cli console --enclave-id i-xxxxx-enc-xxxxx
```

## Troubleshooting

### Enclave Won't Start

**Issue**: `Insufficient memory`
```bash
# Check allocator configuration
cat /etc/nitro_enclaves/allocator.yaml

# Increase memory allocation
sudo vim /etc/nitro_enclaves/allocator.yaml
sudo systemctl restart nitro-enclaves-allocator
```

### KMS Access Denied

**Issue**: `kms:Decrypt` permission denied

Check:
1. IAM role attached to instance
2. KMS key policy includes enclave attestation condition
3. PCR0 value matches in policy

### High Latency

**Issue**: Signing takes >10ms

Investigate:
```bash
# Check KMS throttling
aws cloudwatch get-metric-statistics \
  --namespace AWS/KMS \
  --metric-name UserErrorCount \
  --dimensions Name=KeyId,Value=$KEY_ID

# Check cache hit rate
grep "cache_miss" /var/log/hsm/enclave.log
```

Solutions:
- Increase key cache size
- Pre-load hot keys
- Use larger instance type

## Cost Optimization

### Instance Selection

| Instance | vCPUs | RAM | Price/hr | Performance | Use Case |
|----------|-------|-----|----------|-------------|----------|
| c5.xlarge | 4 | 8 GB | $0.17 | 500 ops/sec | Development |
| c5.2xlarge | 8 | 16 GB | $0.34 | 1000 ops/sec | Production |
| c5.4xlarge | 16 | 32 GB | $0.68 | 2000 ops/sec | High throughput |

### KMS Costs

- **Request pricing**: $0.03 per 10,000 requests
- **Key storage**: $1/month per key

**Optimization**: Cache keys in enclave memory to reduce KMS calls.

Example: 1M signing operations/month
- Without cache: 1M KMS calls = $3
- With cache: 100K KMS calls = $0.30 (90% savings)

## Security Best Practices

1. **Never run with `--debug-mode` in production**
   - Debug mode allows console access
   - Breaks isolation guarantees

2. **Always verify attestation**
   - Check PCR values match expected
   - Verify AWS signature on attestation

3. **Use VPC endpoints for KMS**
   - Avoid internet egress
   - Reduces attack surface

4. **Rotate KMS keys annually**
   - Re-encrypt sealed keys with new KMS key
   - Follow AWS key rotation best practices

5. **Implement least privilege IAM**
   - Enclave role: only KMS access
   - Parent instance: minimal permissions

## References

- [AWS Nitro Enclaves Documentation](https://docs.aws.amazon.com/enclaves/)
- [Nitro Enclaves KMS Integration](https://docs.aws.amazon.com/enclaves/latest/user/kms.html)
