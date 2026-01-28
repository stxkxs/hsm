// Authentication types
export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  user: User;
  expires_at: string;
}

export interface MeResponse {
  user: User;
  session_id: string;
  created_at: string;
}

export interface User {
  username: string;
  roles: string[];
  namespace: string;
}

// Key types
export interface Key {
  key_id: string;
  algorithm: string;
  purpose: string;
  namespace: string;
  public_key?: string;
  created_at: string;
  last_used?: string;
  labels: Record<string, string>;
  active: boolean;
}

export interface ListKeysResponse {
  keys: Key[];
  total: number;
  next_cursor?: string;
}

export interface CreateKeyRequest {
  algorithm: string;
  purpose: string;
  namespace?: string;
  labels?: Record<string, string>;
}

export interface CreateKeyResponse {
  key_id: string;
  algorithm: string;
  purpose: string;
  public_key?: string;
  created_at: string;
}

// Crypto operations types
export interface SignRequest {
  data: string;
}

export interface SignResponse {
  signature: string;
  key_id: string;
  algorithm: string;
}

export interface VerifyRequest {
  data: string;
  signature: string;
}

export interface VerifyResponse {
  valid: boolean;
  key_id: string;
}

export interface EncryptRequest {
  plaintext: string;
}

export interface EncryptResponse {
  ciphertext: string;
  nonce: string;
  key_id: string;
}

export interface DecryptRequest {
  ciphertext: string;
  nonce: string;
}

export interface DecryptResponse {
  plaintext: string;
  key_id: string;
}

// Blockchain types
export interface Wallet {
  id: string;
  name: string;
  created_at: string;
  derived_keys_count: number;
}

export interface DeriveKeyRequest {
  path: string;
}

export interface DeriveKeyResponse {
  key_id: string;
  public_key: string;
  path: string;
  chain_code?: string;
}

export interface SignEip191Request {
  key_id: string;
  message: string;
}

export interface SignEip712Request {
  key_id: string;
  typed_data: Eip712TypedData;
}

export interface Eip712TypedData {
  types: Record<string, Eip712Type[]>;
  primaryType: string;
  domain: Eip712Domain;
  message: Record<string, unknown>;
}

export interface Eip712Type {
  name: string;
  type: string;
}

export interface Eip712Domain {
  name?: string;
  version?: string;
  chainId?: number;
  verifyingContract?: string;
  salt?: string;
}

export interface SignatureResponse {
  signature: string;
  r: string;
  s: string;
  v: number;
}

export interface AddressRequest {
  key_id: string;
  chains: string[];
}

export interface AddressResponse {
  addresses: Record<string, string>;
}

// Audit types
export interface AuditEntry {
  id: string;
  timestamp: string;
  operation: string;
  actor: string;
  resource_type: string;
  resource_id: string;
  status: "success" | "failure";
  details?: Record<string, unknown>;
  hash: string;
  previous_hash: string;
}

export interface AuditParams {
  start_time?: string;
  end_time?: string;
  operation?: string;
  actor?: string;
  resource_id?: string;
  status?: "success" | "failure";
  limit?: number;
  cursor?: string;
}

export interface AuditResponse {
  entries: AuditEntry[];
  next_cursor?: string;
  total_count: number;
}

// Webhook types
export interface Webhook {
  id: string;
  url: string;
  events: string[];
  status: "active" | "inactive";
  secret_hash: string;
  created_at: string;
  last_triggered?: string;
  failure_count: number;
}

export interface WebhookRequest {
  url: string;
  events: string[];
  secret: string;
}

export interface WebhookDelivery {
  id: string;
  webhook_id: string;
  event: string;
  status: "success" | "failure" | "pending";
  response_code?: number;
  attempted_at: string;
  next_retry?: string;
}

// Policy types
export interface Policy {
  id: string;
  name: string;
  description?: string;
  wasm_hash: string;
  fuel_limit: number;
  memory_limit: number;
  created_at: string;
  attached_namespaces: string[];
}

export interface PolicyRequest {
  name: string;
  description?: string;
  wasm: File;
  fuel_limit?: number;
  memory_limit?: number;
}

// Namespace types
export interface Namespace {
  name: string;
  created_at: string;
  key_count: number;
  policies: string[];
}

// API response wrapper
export interface ApiResponse<T> {
  data?: T;
  error?: ApiError;
}

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

// Health check types
export interface HealthResponse {
  status: "healthy" | "unhealthy";
  version: string;
  uptime_seconds: number;
}

export interface ReadyResponse {
  ready: boolean;
  checks: Record<string, boolean>;
}
