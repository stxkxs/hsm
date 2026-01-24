/**
 * HSM Client Types
 *
 * Type definitions for the HSM TypeScript SDK.
 */

// ============================================================================
// Key Management Types
// ============================================================================

/** Supported key algorithms */
export type KeyAlgorithm =
  | 'ED25519'
  | 'ECDSA_P256'
  | 'ECDSA_P384'
  | 'RSA2048'
  | 'RSA3072'
  | 'RSA4096'
  | 'AES128'
  | 'AES256';

/** Key purpose/usage */
export type KeyPurpose = 'SIGN' | 'ENCRYPT' | 'GENERAL';

/** Key state */
export type KeyState = 'ACTIVE' | 'INACTIVE' | 'COMPROMISED' | 'DESTROYED';

/** Request to generate a new key */
export interface GenerateKeyRequest {
  /** Unique key identifier (optional, generated if not provided) */
  key_id?: string;
  /** Key algorithm */
  algorithm: KeyAlgorithm;
  /** Key purpose */
  purpose: KeyPurpose;
  /** Namespace for the key (default: "default") */
  namespace?: string;
  /** Optional labels/tags for the key */
  labels?: Record<string, string>;
}

/** Response after generating a key */
export interface GenerateKeyResponse {
  /** Generated key ID */
  key_id: string;
  /** Key algorithm */
  algorithm: KeyAlgorithm;
  /** Key purpose */
  purpose: KeyPurpose;
  /** Public key (base64-encoded, for asymmetric keys) */
  public_key?: string;
  /** Creation timestamp (RFC 3339) */
  created_at: string;
}

/** Key metadata */
export interface KeyMetadata {
  /** Key ID */
  key_id: string;
  /** Key algorithm */
  algorithm: KeyAlgorithm;
  /** Key purpose */
  purpose: KeyPurpose;
  /** Namespace */
  namespace: string;
  /** Public key (base64-encoded, for asymmetric keys) */
  public_key?: string;
  /** Creation timestamp */
  created_at: string;
  /** Last used timestamp */
  last_used?: string;
  /** Key labels */
  labels: Record<string, string>;
  /** Whether the key is active */
  active: boolean;
}

/** List keys response */
export interface ListKeysResponse {
  /** List of keys */
  keys: KeyMetadata[];
  /** Total count (for pagination) */
  total: number;
  /** Next page cursor (if more results available) */
  next_cursor?: string;
}

/** List keys options */
export interface ListKeysOptions {
  /** Namespace filter */
  namespace?: string;
  /** Maximum results per page */
  limit?: number;
  /** Pagination cursor */
  cursor?: string;
  /** State filter */
  state?: KeyState;
}

// ============================================================================
// Cryptographic Operation Types
// ============================================================================

/** Request to sign data */
export interface SignRequest {
  /** Data to sign (base64-encoded or raw bytes) */
  data: string | Uint8Array;
  /** Optional hash algorithm (defaults to SHA-256) */
  hash_algorithm?: string;
}

/** Sign response */
export interface SignResponse {
  /** Signature (base64-encoded) */
  signature: string;
  /** Algorithm used */
  algorithm: string;
}

/** Request to verify a signature */
export interface VerifyRequest {
  /** Original data (base64-encoded or raw bytes) */
  data: string | Uint8Array;
  /** Signature to verify (base64-encoded) */
  signature: string;
}

/** Verify response */
export interface VerifyResponse {
  /** Whether the signature is valid */
  valid: boolean;
}

/** Request to encrypt data */
export interface EncryptRequest {
  /** Plaintext data (base64-encoded or raw bytes) */
  plaintext: string | Uint8Array;
  /** Optional additional authenticated data (base64-encoded) */
  aad?: string;
}

/** Encrypt response */
export interface EncryptResponse {
  /** Ciphertext (base64-encoded) */
  ciphertext: string;
  /** Nonce/IV (base64-encoded) */
  nonce: string;
  /** Authentication tag (base64-encoded, for AEAD) */
  tag?: string;
}

/** Request to decrypt data */
export interface DecryptRequest {
  /** Ciphertext (base64-encoded) */
  ciphertext: string;
  /** Nonce/IV (base64-encoded) */
  nonce: string;
  /** Authentication tag (base64-encoded, for AEAD) */
  tag?: string;
  /** Optional additional authenticated data (base64-encoded) */
  aad?: string;
}

/** Decrypt response */
export interface DecryptResponse {
  /** Decrypted plaintext (base64-encoded) */
  plaintext: string;
}

// ============================================================================
// Batch Operation Types
// ============================================================================

/** Batch sign request */
export interface BatchSignRequest {
  /** List of sign requests */
  requests: Array<{ key_id: string } & SignRequest>;
}

/** Batch sign response */
export interface BatchSignResponse {
  /** Results (signature or error for each request) */
  results: Array<SignResponse | { error: string }>;
}

/** Batch verify request */
export interface BatchVerifyRequest {
  /** List of verify requests */
  requests: Array<{ key_id: string } & VerifyRequest>;
}

/** Batch verify response */
export interface BatchVerifyResponse {
  /** Results (valid or error for each request) */
  results: Array<VerifyResponse | { error: string }>;
}

/** Batch encrypt request */
export interface BatchEncryptRequest {
  /** List of encrypt requests */
  requests: Array<{ key_id: string } & EncryptRequest>;
}

/** Batch encrypt response */
export interface BatchEncryptResponse {
  /** Results (ciphertext or error for each request) */
  results: Array<EncryptResponse | { error: string }>;
}

/** Batch decrypt request */
export interface BatchDecryptRequest {
  /** List of decrypt requests */
  requests: Array<{ key_id: string } & DecryptRequest>;
}

/** Batch decrypt response */
export interface BatchDecryptResponse {
  /** Results (plaintext or error for each request) */
  results: Array<DecryptResponse | { error: string }>;
}

// ============================================================================
// Audit Types
// ============================================================================

/** Audit log entry */
export interface AuditEntry {
  /** Entry ID */
  id: string;
  /** Timestamp (RFC 3339) */
  timestamp: string;
  /** Event type */
  event_type: string;
  /** Actor (client identity) */
  actor: string;
  /** Resource (key ID, namespace, etc.) */
  resource?: string;
  /** Action performed */
  action: string;
  /** Result (success/failure) */
  result: string;
  /** Additional details (sanitized) */
  details?: string;
}

/** Audit log response */
export interface AuditLogResponse {
  /** Audit entries */
  entries: AuditEntry[];
  /** Total count */
  total: number;
  /** Next page cursor */
  next_cursor?: string;
}

/** Audit log query options */
export interface AuditLogOptions {
  /** Namespace filter */
  namespace?: string;
  /** Start time (RFC 3339 or Date) */
  start_time?: string | Date;
  /** End time (RFC 3339 or Date) */
  end_time?: string | Date;
  /** User ID filter */
  user_id?: string;
  /** Operation filter */
  operation?: string;
  /** Maximum results per page */
  limit?: number;
  /** Pagination cursor */
  cursor?: string;
}

// ============================================================================
// Health Types
// ============================================================================

/** Health check response */
export interface HealthResponse {
  /** Service status */
  status: 'healthy' | 'degraded' | 'unhealthy';
  /** Service version */
  version: string;
  /** Uptime in seconds */
  uptime_seconds: number;
}

/** Readiness check response */
export interface ReadyResponse {
  /** Whether the service is ready */
  ready: boolean;
  /** Component status */
  components: Record<string, ComponentStatus>;
}

/** Component status for readiness check */
export interface ComponentStatus {
  /** Component status */
  status: 'healthy' | 'degraded' | 'unhealthy';
  /** Optional message */
  message?: string;
}

// ============================================================================
// Client Configuration Types
// ============================================================================

/** HSM Client configuration */
export interface HsmClientConfig {
  /** Base URL of the HSM server */
  baseUrl: string;
  /** Session ID for authentication */
  sessionId?: string;
  /** Session token for authentication */
  sessionToken?: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
  /** Custom headers to include in requests */
  headers?: Record<string, string>;
  /** Retry configuration */
  retry?: RetryConfig;
}

/** Retry configuration */
export interface RetryConfig {
  /** Maximum number of retries (default: 3) */
  maxRetries?: number;
  /** Base delay in milliseconds (default: 100) */
  baseDelay?: number;
  /** Maximum delay in milliseconds (default: 5000) */
  maxDelay?: number;
  /** Jitter factor (0-1, default: 0.1) */
  jitter?: number;
  /** Retry on these status codes (default: [429, 502, 503, 504]) */
  retryOnStatus?: number[];
}

/** Session scope for limiting session capabilities */
export interface SessionScope {
  /** Allowed operations (permissions) */
  allowedOperations?: string[];
  /** Allowed key IDs */
  allowedKeys?: string[];
  /** Maximum total operations in this session */
  maxOperations?: number;
  /** Per-second rate limit */
  rateLimit?: number;
}
