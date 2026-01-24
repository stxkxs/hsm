# HSM Client SDKs

Official client libraries for integrating with HSM in your preferred language.

## Installation

### TypeScript / JavaScript

```bash
npm install @anthropic/hsm-client
```

### Python

```bash
pip install hsm-client
```

### Go

```bash
go get github.com/anthropic/hsm/sdks/go
```

### Rust

```toml
[dependencies]
hsm-client = "0.1"
```

## Quick Start

### TypeScript

```typescript
import { HsmClient } from '@anthropic/hsm-client';

const client = new HsmClient({
  baseUrl: 'https://hsm.example.com',
  apiKey: process.env.HSM_API_KEY,
});

// generate a key
const key = await client.keys.create({
  algorithm: 'ed25519',
  name: 'my-signing-key',
});

// sign a message
const signature = await client.crypto.sign({
  keyId: key.id,
  message: Buffer.from('hello world'),
});

// verify
const valid = await client.crypto.verify({
  keyId: key.id,
  message: Buffer.from('hello world'),
  signature,
});
```

### Python

```python
import asyncio
from hsm_client import HsmClient

async def main():
    async with HsmClient(
        base_url="https://hsm.example.com",
        api_key=os.environ["HSM_API_KEY"],
    ) as client:
        # generate a key
        key = await client.keys.create(
            algorithm="ed25519",
            name="my-signing-key",
        )

        # sign a message
        signature = await client.crypto.sign(
            key_id=key.id,
            message=b"hello world",
        )

        # verify
        valid = await client.crypto.verify(
            key_id=key.id,
            message=b"hello world",
            signature=signature,
        )

asyncio.run(main())
```

### Go

```go
package main

import (
    "context"
    "os"

    hsm "github.com/anthropic/hsm/sdks/go"
)

func main() {
    client := hsm.NewClient(
        hsm.WithBaseURL("https://hsm.example.com"),
        hsm.WithAPIKey(os.Getenv("HSM_API_KEY")),
    )

    ctx := context.Background()

    // generate a key
    key, err := client.Keys.Create(ctx, &hsm.CreateKeyRequest{
        Algorithm: "ed25519",
        Name:      "my-signing-key",
    })

    // sign a message
    signature, err := client.Crypto.Sign(ctx, &hsm.SignRequest{
        KeyID:   key.ID,
        Message: []byte("hello world"),
    })

    // verify
    valid, err := client.Crypto.Verify(ctx, &hsm.VerifyRequest{
        KeyID:     key.ID,
        Message:   []byte("hello world"),
        Signature: signature,
    })
}
```

### Rust

```rust
use hsm_client::{HsmClient, Config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = HsmClient::new(Config {
        base_url: "https://hsm.example.com".into(),
        api_key: std::env::var("HSM_API_KEY")?,
        ..Default::default()
    })?;

    // generate a key
    let key = client.keys().create("ed25519", "my-signing-key").await?;

    // sign a message
    let signature = client.crypto().sign(&key.id, b"hello world").await?;

    // verify
    let valid = client.crypto().verify(&key.id, b"hello world", &signature).await?;

    Ok(())
}
```

## Features

All SDKs support:

| Feature | Description |
|---------|-------------|
| Key Management | create, import, export, rotate, delete keys |
| Signing | ed25519, ecdsa (p-256/p-384/secp256k1), rsa, bls12-381, schnorr |
| Encryption | aes-256-gcm, aes-128-gcm, rsa-oaep |
| Hashing | sha-256, sha-384, sha-512, sha3 |
| Batch Operations | sign/verify/encrypt multiple items in one request |
| Streaming | stream audit logs in real-time |
| Session Management | automatic token refresh, session scoping |
| Retry Logic | exponential backoff with jitter |

## Authentication

All SDKs support multiple authentication methods:

```typescript
// api key
const client = new HsmClient({ apiKey: 'hsm_...' });

// mtls
const client = new HsmClient({
  mtls: {
    cert: fs.readFileSync('client.crt'),
    key: fs.readFileSync('client.key'),
  },
});

// oidc
const client = new HsmClient({
  oidc: {
    issuer: 'https://auth.example.com',
    clientId: 'hsm-client',
    clientSecret: process.env.OIDC_SECRET,
  },
});
```

## Error Handling

All SDKs use typed errors:

```typescript
import { HsmError, RateLimitError, KeyNotFoundError } from '@anthropic/hsm-client';

try {
  await client.keys.get('nonexistent');
} catch (e) {
  if (e instanceof KeyNotFoundError) {
    console.log('key does not exist');
  } else if (e instanceof RateLimitError) {
    console.log(`rate limited, retry after ${e.retryAfter}s`);
  } else if (e instanceof HsmError) {
    console.log(`hsm error: ${e.code} - ${e.message}`);
  }
}
```

## gRPC Support

Go and Rust SDKs also support gRPC for lower latency:

```go
client := hsm.NewClient(
    hsm.WithGRPC("hsm.example.com:9090"),
    hsm.WithTLS(tlsConfig),
)
```

```rust
let client = HsmClient::new_grpc("https://hsm.example.com:9090", tls_config)?;
```

## Connection Pooling

All SDKs maintain connection pools for performance:

```typescript
const client = new HsmClient({
  baseUrl: 'https://hsm.example.com',
  pool: {
    maxConnections: 100,
    idleTimeout: 30_000,
  },
});
```

## Timeouts

Configure request timeouts:

```python
client = HsmClient(
    base_url="https://hsm.example.com",
    timeout=30.0,  # seconds
    connect_timeout=5.0,
)
```

## Observability

SDKs emit metrics and support tracing:

```go
import "go.opentelemetry.io/otel"

client := hsm.NewClient(
    hsm.WithTracer(otel.Tracer("hsm-client")),
    hsm.WithMetrics(promRegistry),
)
```
