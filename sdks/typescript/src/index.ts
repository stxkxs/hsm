/**
 * HSM TypeScript SDK
 *
 * Official TypeScript SDK for HSM (Hardware Security Module).
 *
 * @packageDocumentation
 *
 * @example Basic Usage
 * ```typescript
 * import { createClient } from '@hsm/client';
 *
 * const client = createClient({
 *   baseUrl: 'https://hsm.example.com',
 *   sessionId: 'session-id',
 *   sessionToken: 'session-token',
 * });
 *
 * // Generate a key
 * const key = await client.keys.generateEd25519({ namespace: 'my-app' });
 *
 * // Sign data
 * const { signature } = await client.sign(key.key_id, {
 *   data: 'Hello, World!',
 * });
 *
 * // Verify signature
 * const { valid } = await client.verify(key.key_id, {
 *   data: 'Hello, World!',
 *   signature,
 * });
 *
 * console.log('Signature valid:', valid);
 * ```
 *
 * @example Key Management
 * ```typescript
 * // Generate different key types
 * const ed25519Key = await client.keys.generateEd25519();
 * const ecdsaKey = await client.keys.generateEcdsaP256();
 * const rsaKey = await client.keys.generateRsa({ size: 4096 });
 * const aesKey = await client.keys.generateAes({ size: 256 });
 *
 * // List keys with pagination
 * for await (const key of client.keys.listAll({ namespace: 'my-app' })) {
 *   console.log(key.key_id, key.algorithm);
 * }
 * ```
 *
 * @example Batch Operations
 * ```typescript
 * const messages = ['message1', 'message2', 'message3'];
 *
 * const { results } = await client.batchSign({
 *   requests: messages.map((msg) => ({
 *     key_id: key.key_id,
 *     data: msg,
 *   })),
 * });
 * ```
 *
 * @example Error Handling
 * ```typescript
 * import {
 *   HsmError,
 *   AuthenticationError,
 *   NotFoundError,
 *   RateLimitError,
 * } from '@hsm/client';
 *
 * try {
 *   await client.sign('nonexistent-key', { data: 'test' });
 * } catch (error) {
 *   if (error instanceof NotFoundError) {
 *     console.log('Key not found');
 *   } else if (error instanceof RateLimitError) {
 *     console.log('Rate limited, retry after:', error.retryAfter);
 *   } else if (error instanceof HsmError) {
 *     console.log('HSM error:', error.message, error.code);
 *   }
 * }
 * ```
 */

// Main client
export { HsmClient, createClient } from './client';

// Types
export type {
  // Client config
  HsmClientConfig,
  RetryConfig,
  SessionScope,
  // Key management
  KeyAlgorithm,
  KeyPurpose,
  KeyState,
  GenerateKeyRequest,
  GenerateKeyResponse,
  KeyMetadata,
  ListKeysResponse,
  ListKeysOptions,
  // Cryptographic operations
  SignRequest,
  SignResponse,
  VerifyRequest,
  VerifyResponse,
  EncryptRequest,
  EncryptResponse,
  DecryptRequest,
  DecryptResponse,
  // Batch operations
  BatchSignRequest,
  BatchSignResponse,
  BatchVerifyRequest,
  BatchVerifyResponse,
  BatchEncryptRequest,
  BatchEncryptResponse,
  BatchDecryptRequest,
  BatchDecryptResponse,
  // Audit
  AuditEntry,
  AuditLogResponse,
  AuditLogOptions,
  // Health
  HealthResponse,
  ReadyResponse,
  ComponentStatus,
} from './types';

// Errors
export {
  HsmError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ValidationError,
  RateLimitError,
  NetworkError,
  TimeoutError,
  ServerError,
  CryptoError,
  SessionError,
} from './errors';

// Auth utilities
export {
  TokenManager,
  CircuitBreaker,
  RetryStrategy,
  ScopeValidator,
} from './auth';

// Key management utilities
export { KeyManager } from './keys';

// Crypto utilities
export {
  toBase64,
  fromBase64,
  isBase64,
  toHex,
  fromHex,
  normalizeToBase64,
  sha256,
  keccak256,
  createMessageHash,
  constantTimeEqual,
  randomBytes,
  concatBytes,
  splitBytes,
  derToRaw,
  rawToDer,
} from './crypto';
