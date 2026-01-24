# HSM Clustering & High Availability

Deploy HSM in a clustered configuration for 99.99% uptime with automatic failover.

## Architecture

```
                    ┌─────────────────────┐
                    │   Load Balancer     │
                    │  (health-aware)     │
                    └──────────┬──────────┘
                               │
           ┌───────────────────┼───────────────────┐
           │                   │                   │
           ▼                   ▼                   ▼
    ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
    │   Node 1    │     │   Node 2    │     │   Node 3    │
    │  (Leader)   │◄───►│ (Follower)  │◄───►│ (Follower)  │
    │             │     │             │     │             │
    │ ┌─────────┐ │     │ ┌─────────┐ │     │ ┌─────────┐ │
    │ │Key Store│ │     │ │Key Store│ │     │ │Key Store│ │
    │ └─────────┘ │     │ └─────────┘ │     │ └─────────┘ │
    │ ┌─────────┐ │     │ ┌─────────┐ │     │ ┌─────────┐ │
    │ │Raft Log │ │     │ │Raft Log │ │     │ │Raft Log │ │
    │ └─────────┘ │     │ └─────────┘ │     │ └─────────┘ │
    └─────────────┘     └─────────────┘     └─────────────┘
```

## How It Works

HSM uses Raft consensus to maintain consistency across nodes:

1. **Leader Election**: nodes elect a leader via raft voting
2. **Log Replication**: all writes go through the leader and replicate to followers
3. **Consistency**: reads can be served by any node (with leader lease validation)
4. **Failover**: if leader fails, followers elect a new leader (<5 seconds)

## Configuration

### Basic 3-Node Cluster

```toml
# config.toml

[cluster]
enabled = true
node_id = "node-1"
bind_addr = "0.0.0.0:7000"

# peer nodes
[[cluster.peers]]
id = "node-2"
addr = "10.0.1.2:7000"

[[cluster.peers]]
id = "node-3"
addr = "10.0.1.3:7000"

[cluster.raft]
election_timeout_ms = 300
heartbeat_interval_ms = 100
snapshot_threshold = 10000

[cluster.transport]
tls_cert = "/etc/hsm/cluster.crt"
tls_key = "/etc/hsm/cluster.key"
tls_ca = "/etc/hsm/cluster-ca.crt"
```

### Environment Variables

```bash
HSM_CLUSTER_ENABLED=true
HSM_CLUSTER_NODE_ID=node-1
HSM_CLUSTER_BIND_ADDR=0.0.0.0:7000
HSM_CLUSTER_PEERS=node-2:10.0.1.2:7000,node-3:10.0.1.3:7000
```

## Deployment

### Kubernetes

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: hsm
spec:
  serviceName: hsm
  replicas: 3
  selector:
    matchLabels:
      app: hsm
  template:
    metadata:
      labels:
        app: hsm
    spec:
      containers:
      - name: hsm
        image: hsm:latest
        env:
        - name: HSM_CLUSTER_ENABLED
          value: "true"
        - name: HSM_CLUSTER_NODE_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: HSM_CLUSTER_PEERS
          value: "hsm-0:hsm-0.hsm:7000,hsm-1:hsm-1.hsm:7000,hsm-2:hsm-2.hsm:7000"
        ports:
        - containerPort: 8080
          name: api
        - containerPort: 7000
          name: cluster
        volumeMounts:
        - name: data
          mountPath: /var/lib/hsm
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
---
apiVersion: v1
kind: Service
metadata:
  name: hsm
spec:
  clusterIP: None  # headless for statefulset
  selector:
    app: hsm
  ports:
  - port: 7000
    name: cluster
---
apiVersion: v1
kind: Service
metadata:
  name: hsm-api
spec:
  selector:
    app: hsm
  ports:
  - port: 8080
    name: api
```

### Docker Compose

```yaml
version: '3.8'

services:
  hsm-1:
    image: hsm:latest
    environment:
      HSM_CLUSTER_ENABLED: "true"
      HSM_CLUSTER_NODE_ID: node-1
      HSM_CLUSTER_BIND_ADDR: "0.0.0.0:7000"
      HSM_CLUSTER_PEERS: "node-2:hsm-2:7000,node-3:hsm-3:7000"
    ports:
      - "8081:8080"
    volumes:
      - hsm-1-data:/var/lib/hsm

  hsm-2:
    image: hsm:latest
    environment:
      HSM_CLUSTER_ENABLED: "true"
      HSM_CLUSTER_NODE_ID: node-2
      HSM_CLUSTER_BIND_ADDR: "0.0.0.0:7000"
      HSM_CLUSTER_PEERS: "node-1:hsm-1:7000,node-3:hsm-3:7000"
    ports:
      - "8082:8080"
    volumes:
      - hsm-2-data:/var/lib/hsm

  hsm-3:
    image: hsm:latest
    environment:
      HSM_CLUSTER_ENABLED: "true"
      HSM_CLUSTER_NODE_ID: node-3
      HSM_CLUSTER_BIND_ADDR: "0.0.0.0:7000"
      HSM_CLUSTER_PEERS: "node-1:hsm-1:7000,node-2:hsm-2:7000"
    ports:
      - "8083:8080"
    volumes:
      - hsm-3-data:/var/lib/hsm

volumes:
  hsm-1-data:
  hsm-2-data:
  hsm-3-data:
```

## Operations

### Check Cluster Status

```bash
curl http://localhost:8080/cluster/status
```

```json
{
  "node_id": "node-1",
  "state": "leader",
  "term": 42,
  "leader_id": "node-1",
  "peers": [
    {"id": "node-2", "state": "follower", "last_seen": "2024-01-15T10:30:00Z"},
    {"id": "node-3", "state": "follower", "last_seen": "2024-01-15T10:30:00Z"}
  ],
  "commit_index": 12345,
  "applied_index": 12345
}
```

### Force Leader Election

If needed, you can trigger a new election:

```bash
curl -X POST http://localhost:8080/cluster/step-down
```

### Add a Node

1. Start the new node with existing peers configured
2. The new node will automatically join and sync

```bash
# on new node
HSM_CLUSTER_NODE_ID=node-4 \
HSM_CLUSTER_PEERS=node-1:10.0.1.1:7000,node-2:10.0.1.2:7000,node-3:10.0.1.3:7000 \
hsm-server
```

### Remove a Node

1. Ensure cluster has quorum without the node
2. Stop the node
3. Remove from peer configuration on remaining nodes

### Backup & Restore

Cluster state is backed up via raft snapshots:

```bash
# trigger snapshot
curl -X POST http://localhost:8080/cluster/snapshot

# snapshots stored in /var/lib/hsm/snapshots/
```

## Anti-Double-Signing

In cluster mode, HSM enforces anti-double-signing for validator keys:

1. Before signing, a `RecordSigningAttempt` command is committed to raft
2. Only after quorum confirms the record does signing proceed
3. This prevents double-signing even during leader transitions

Supported protocols:
- **Ethereum**: attestation and block double-vote detection
- **Babylon**: EOTS height tracking (any second signature reveals private key)

## Split-Brain Prevention

Raft quorum ensures no split-brain:

| Nodes | Quorum | Can Tolerate |
|-------|--------|--------------|
| 3     | 2      | 1 failure    |
| 5     | 3      | 2 failures   |
| 7     | 4      | 3 failures   |

A minority partition becomes read-only until it rejoins the majority.

## Transport Security

All cluster communication is encrypted:

- **TLS 1.3** for peer connections
- **AES-256-GCM** for log entry encryption
- **HKDF** for per-epoch key derivation
- Automatic key rotation on configurable schedule

## Monitoring

### Metrics

| Metric | Description |
|--------|-------------|
| `hsm_cluster_state` | current node state (leader/follower/candidate) |
| `hsm_cluster_term` | current raft term |
| `hsm_cluster_commit_index` | committed log index |
| `hsm_cluster_apply_latency` | time to apply commands |
| `hsm_cluster_replication_lag` | follower replication delay |
| `hsm_cluster_election_count` | number of elections |

### Alerts

Recommended alerts:

```yaml
# no leader for >10s
- alert: HsmClusterNoLeader
  expr: sum(hsm_cluster_state{state="leader"}) == 0
  for: 10s

# replication lag >1s
- alert: HsmClusterReplicationLag
  expr: hsm_cluster_replication_lag > 1
  for: 30s

# frequent elections
- alert: HsmClusterUnstable
  expr: increase(hsm_cluster_election_count[5m]) > 3
```

## Troubleshooting

### Node Won't Join

1. Check network connectivity: `nc -zv peer-ip 7000`
2. Verify TLS certificates match cluster CA
3. Ensure node IDs are unique
4. Check firewall allows port 7000

### Slow Replication

1. Check network latency between nodes
2. Increase `heartbeat_interval_ms` if network is slow
3. Monitor disk I/O on followers
4. Consider SSD storage for raft log

### Frequent Elections

1. Increase `election_timeout_ms` (default 300ms)
2. Check for network partitions
3. Ensure nodes have stable clocks (use NTP)
4. Review system resource usage (CPU, memory)
