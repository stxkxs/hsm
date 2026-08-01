/**
 * HSM Client
 *
 * Main client class for interacting with the HSM server.
 */

import { CircuitBreaker, RetryStrategy, TokenManager } from './auth';
import { normalizeToBase64 } from './crypto';
import { HsmError, NetworkError, parseErrorResponse, TimeoutError } from './errors';
import { KeyManager, type KeyManagerClient } from './keys';
import type {
  AuditLogOptions,
  AuditLogResponse,
  BatchDecryptRequest,
  BatchDecryptResponse,
  BatchEncryptRequest,
  BatchEncryptResponse,
  BatchSignRequest,
  BatchSignResponse,
  BatchVerifyRequest,
  BatchVerifyResponse,
  DecryptRequest,
  DecryptResponse,
  EncryptRequest,
  EncryptResponse,
  GenerateKeyRequest,
  GenerateKeyResponse,
  HealthResponse,
  HsmClientConfig,
  KeyMetadata,
  ListKeysOptions,
  ListKeysResponse,
  ReadyResponse,
  SignRequest,
  SignResponse,
  VerifyRequest,
  VerifyResponse,
} from './types';

/** HSM Client for interacting with HSM server */
export class HsmClient implements KeyManagerClient {
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly headers: Record<string, string>;
  private readonly tokenManager: TokenManager;
  private readonly circuitBreaker: CircuitBreaker;
  private readonly retryStrategy: RetryStrategy;

  /** Key management operations */
  public readonly keys: KeyManager;

  constructor(config: HsmClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.timeout = config.timeout ?? 30000;
    this.headers = config.headers ?? {};
    this.tokenManager = new TokenManager({
      sessionId: config.sessionId,
      sessionToken: config.sessionToken,
    });
    this.circuitBreaker = new CircuitBreaker();
    this.retryStrategy = new RetryStrategy(config.retry);
    this.keys = new KeyManager(this);
  }

  // ===========================================================================
  // HTTP Request Helpers
  // ===========================================================================

  private async request<T>(method: string, path: string, body?: unknown, attempt = 0): Promise<T> {
    // Check circuit breaker
    if (!this.circuitBreaker.canRequest()) {
      throw new HsmError('Circuit breaker is open', { code: 'CIRCUIT_OPEN' });
    }

    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...this.headers,
    };

    // Add authorization header if authenticated
    const authHeader = this.tokenManager.getAuthorizationHeader();
    if (authHeader) {
      headers.Authorization = authHeader;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({}));

        // Check if we should retry
        if (this.retryStrategy.shouldRetry(response.status, attempt)) {
          this.circuitBreaker.recordFailure();
          await this.retryStrategy.sleep(attempt);
          return this.request(method, path, body, attempt + 1);
        }

        this.circuitBreaker.recordFailure();
        throw parseErrorResponse(response.status, errorBody);
      }

      this.circuitBreaker.recordSuccess();
      await this.tokenManager.incrementOperationCount();

      // Handle empty responses
      const text = await response.text();
      if (!text) {
        return {} as T;
      }

      return JSON.parse(text) as T;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof HsmError) {
        throw error;
      }

      if (error instanceof Error) {
        if (error.name === 'AbortError') {
          this.circuitBreaker.recordFailure();
          throw new TimeoutError();
        }

        // Check if we should retry network errors
        if (this.retryStrategy.shouldRetryError(error, attempt)) {
          this.circuitBreaker.recordFailure();
          await this.retryStrategy.sleep(attempt);
          return this.request(method, path, body, attempt + 1);
        }

        this.circuitBreaker.recordFailure();
        throw new NetworkError(error.message, { cause: error });
      }

      throw new HsmError('Unknown error occurred');
    }
  }

  private get<T>(path: string): Promise<T> {
    return this.request('GET', path);
  }

  private post<T>(path: string, body?: unknown): Promise<T> {
    return this.request('POST', path, body);
  }

  private delete<T>(path: string): Promise<T> {
    return this.request('DELETE', path);
  }

  // ===========================================================================
  // Authentication
  // ===========================================================================

  /** Set session credentials */
  setCredentials(sessionId: string, sessionToken: string): void {
    this.tokenManager.setCredentials(sessionId, sessionToken);
  }

  /** Clear session credentials */
  clearCredentials(): void {
    this.tokenManager.clearCredentials();
  }

  /** Check if client is authenticated */
  isAuthenticated(): boolean {
    return this.tokenManager.isAuthenticated();
  }

  // ===========================================================================
  // Health Check
  // ===========================================================================

  /** Check server health */
  async health(): Promise<HealthResponse> {
    return this.get('/health');
  }

  /** Check server readiness */
  async ready(): Promise<ReadyResponse> {
    return this.get('/ready');
  }

  // ===========================================================================
  // Key Management
  // ===========================================================================

  /** Generate a new key */
  async generateKey(request: GenerateKeyRequest): Promise<GenerateKeyResponse> {
    return this.post('/keys', request);
  }

  /** Get key metadata */
  async getKey(keyId: string): Promise<KeyMetadata> {
    return this.get(`/keys/${encodeURIComponent(keyId)}`);
  }

  /** List keys */
  async listKeys(options?: ListKeysOptions): Promise<ListKeysResponse> {
    const params = new URLSearchParams();
    if (options?.namespace) params.set('namespace', options.namespace);
    if (options?.limit) params.set('limit', options.limit.toString());
    if (options?.cursor) params.set('cursor', options.cursor);
    if (options?.state) params.set('state', options.state);

    const query = params.toString();
    return this.get(`/keys${query ? `?${query}` : ''}`);
  }

  /** Delete a key */
  async deleteKey(keyId: string): Promise<void> {
    await this.delete(`/keys/${encodeURIComponent(keyId)}`);
  }

  // ===========================================================================
  // Cryptographic Operations
  // ===========================================================================

  /** Sign data with a key */
  async sign(keyId: string, request: SignRequest): Promise<SignResponse> {
    const body = {
      data: normalizeToBase64(request.data),
      hash_algorithm: request.hash_algorithm,
    };
    return this.post(`/keys/${encodeURIComponent(keyId)}/sign`, body);
  }

  /** Verify a signature */
  async verify(keyId: string, request: VerifyRequest): Promise<VerifyResponse> {
    const body = {
      data: normalizeToBase64(request.data),
      signature: request.signature,
    };
    return this.post(`/keys/${encodeURIComponent(keyId)}/verify`, body);
  }

  /** Encrypt data with a key */
  async encrypt(keyId: string, request: EncryptRequest): Promise<EncryptResponse> {
    const body = {
      plaintext: normalizeToBase64(request.plaintext),
      aad: request.aad,
    };
    return this.post(`/keys/${encodeURIComponent(keyId)}/encrypt`, body);
  }

  /** Decrypt data with a key */
  async decrypt(keyId: string, request: DecryptRequest): Promise<DecryptResponse> {
    return this.post(`/keys/${encodeURIComponent(keyId)}/decrypt`, request);
  }

  // ===========================================================================
  // Batch Operations
  // ===========================================================================

  /** Sign multiple messages in batch */
  async batchSign(request: BatchSignRequest): Promise<BatchSignResponse> {
    const requests = request.requests.map((r) => ({
      key_id: r.key_id,
      data: normalizeToBase64(r.data),
      hash_algorithm: r.hash_algorithm,
    }));
    return this.post('/keys/batch/sign', { requests });
  }

  /** Verify multiple signatures in batch */
  async batchVerify(request: BatchVerifyRequest): Promise<BatchVerifyResponse> {
    const requests = request.requests.map((r) => ({
      key_id: r.key_id,
      data: normalizeToBase64(r.data),
      signature: r.signature,
    }));
    return this.post('/keys/batch/verify', { requests });
  }

  /** Encrypt multiple messages in batch */
  async batchEncrypt(request: BatchEncryptRequest): Promise<BatchEncryptResponse> {
    const requests = request.requests.map((r) => ({
      key_id: r.key_id,
      plaintext: normalizeToBase64(r.plaintext),
      aad: r.aad,
    }));
    return this.post('/keys/batch/encrypt', { requests });
  }

  /** Decrypt multiple messages in batch */
  async batchDecrypt(request: BatchDecryptRequest): Promise<BatchDecryptResponse> {
    return this.post('/keys/batch/decrypt', request);
  }

  // ===========================================================================
  // Audit
  // ===========================================================================

  /** Get audit log entries */
  async getAuditLog(options?: AuditLogOptions): Promise<AuditLogResponse> {
    const params = new URLSearchParams();
    if (options?.namespace) params.set('namespace', options.namespace);
    if (options?.start_time) {
      const time =
        options.start_time instanceof Date ? options.start_time.toISOString() : options.start_time;
      params.set('start_time', time);
    }
    if (options?.end_time) {
      const time =
        options.end_time instanceof Date ? options.end_time.toISOString() : options.end_time;
      params.set('end_time', time);
    }
    if (options?.user_id) params.set('user_id', options.user_id);
    if (options?.operation) params.set('operation', options.operation);
    if (options?.limit) params.set('limit', options.limit.toString());
    if (options?.cursor) params.set('cursor', options.cursor);

    const query = params.toString();
    return this.get(`/audit${query ? `?${query}` : ''}`);
  }

  /** Stream audit log entries with automatic pagination */
  async *streamAuditLog(
    options?: Omit<AuditLogOptions, 'cursor'>
  ): AsyncGenerator<import('./types').AuditEntry> {
    let cursor: string | undefined;
    do {
      const response = await this.getAuditLog({ ...options, cursor });
      for (const entry of response.entries) {
        yield entry;
      }
      cursor = response.next_cursor;
    } while (cursor);
  }

  // ===========================================================================
  // Utility Methods
  // ===========================================================================

  /** Get the circuit breaker state */
  getCircuitState(): 'closed' | 'open' | 'half-open' {
    return this.circuitBreaker.getState();
  }

  /** Reset the circuit breaker */
  resetCircuitBreaker(): void {
    this.circuitBreaker.reset();
  }

  /** Get the operation count */
  getOperationCount(): number {
    return this.tokenManager.getOperationCount();
  }
}

/**
 * Create a new HSM client
 */
export function createClient(config: HsmClientConfig): HsmClient {
  return new HsmClient(config);
}
