/**
 * HSM Authentication
 *
 * Token management, session handling, and authentication utilities.
 */

import type { SessionScope, RetryConfig } from './types';

/** Token manager for handling session tokens */
export class TokenManager {
  private sessionId: string | null = null;
  private sessionToken: string | null = null;
  private operationCount = 0;
  private readonly maxOperationsBeforeRotation: number;
  private onTokenRotation?: (newToken: string) => Promise<void>;

  constructor(options?: {
    sessionId?: string;
    sessionToken?: string;
    maxOperationsBeforeRotation?: number;
    onTokenRotation?: (newToken: string) => Promise<void>;
  }) {
    this.sessionId = options?.sessionId ?? null;
    this.sessionToken = options?.sessionToken ?? null;
    this.maxOperationsBeforeRotation = options?.maxOperationsBeforeRotation ?? 900;
    this.onTokenRotation = options?.onTokenRotation;
  }

  /** Get the current session ID */
  getSessionId(): string | null {
    return this.sessionId;
  }

  /** Get the current session token */
  getSessionToken(): string | null {
    return this.sessionToken;
  }

  /** Set new credentials */
  setCredentials(sessionId: string, sessionToken: string): void {
    this.sessionId = sessionId;
    this.sessionToken = sessionToken;
    this.operationCount = 0;
  }

  /** Clear credentials */
  clearCredentials(): void {
    this.sessionId = null;
    this.sessionToken = null;
    this.operationCount = 0;
  }

  /** Check if authenticated */
  isAuthenticated(): boolean {
    return this.sessionId !== null && this.sessionToken !== null;
  }

  /** Get authorization header value */
  getAuthorizationHeader(): string | null {
    if (!this.sessionId || !this.sessionToken) {
      return null;
    }
    return `Bearer ${this.sessionId}:${this.sessionToken}`;
  }

  /** Increment operation count and check if rotation is needed */
  async incrementOperationCount(): Promise<boolean> {
    this.operationCount++;
    if (this.operationCount >= this.maxOperationsBeforeRotation && this.onTokenRotation) {
      // Token rotation would be handled here
      return true;
    }
    return false;
  }

  /** Get current operation count */
  getOperationCount(): number {
    return this.operationCount;
  }
}

/** Circuit breaker for resilient connections */
export class CircuitBreaker {
  private state: 'closed' | 'open' | 'half-open' = 'closed';
  private failureCount = 0;
  private lastFailureTime = 0;
  private successCount = 0;

  private readonly failureThreshold: number;
  private readonly recoveryTimeout: number;
  private readonly successThreshold: number;

  constructor(options?: {
    failureThreshold?: number;
    recoveryTimeout?: number;
    successThreshold?: number;
  }) {
    this.failureThreshold = options?.failureThreshold ?? 5;
    this.recoveryTimeout = options?.recoveryTimeout ?? 30000;
    this.successThreshold = options?.successThreshold ?? 2;
  }

  /** Check if request should be allowed */
  canRequest(): boolean {
    if (this.state === 'closed') {
      return true;
    }

    if (this.state === 'open') {
      const timeSinceFailure = Date.now() - this.lastFailureTime;
      if (timeSinceFailure >= this.recoveryTimeout) {
        this.state = 'half-open';
        this.successCount = 0;
        return true;
      }
      return false;
    }

    // half-open: allow limited requests
    return true;
  }

  /** Record a successful request */
  recordSuccess(): void {
    if (this.state === 'half-open') {
      this.successCount++;
      if (this.successCount >= this.successThreshold) {
        this.state = 'closed';
        this.failureCount = 0;
      }
    } else if (this.state === 'closed') {
      this.failureCount = 0;
    }
  }

  /** Record a failed request */
  recordFailure(): void {
    this.failureCount++;
    this.lastFailureTime = Date.now();

    if (this.state === 'half-open') {
      this.state = 'open';
    } else if (this.failureCount >= this.failureThreshold) {
      this.state = 'open';
    }
  }

  /** Get current state */
  getState(): 'closed' | 'open' | 'half-open' {
    return this.state;
  }

  /** Reset the circuit breaker */
  reset(): void {
    this.state = 'closed';
    this.failureCount = 0;
    this.successCount = 0;
  }
}

/** Retry strategy with exponential backoff */
export class RetryStrategy {
  private readonly maxRetries: number;
  private readonly baseDelay: number;
  private readonly maxDelay: number;
  private readonly jitter: number;
  private readonly retryOnStatus: Set<number>;

  constructor(config?: RetryConfig) {
    this.maxRetries = config?.maxRetries ?? 3;
    this.baseDelay = config?.baseDelay ?? 100;
    this.maxDelay = config?.maxDelay ?? 5000;
    this.jitter = config?.jitter ?? 0.1;
    this.retryOnStatus = new Set(config?.retryOnStatus ?? [429, 502, 503, 504]);
  }

  /** Check if status code should be retried */
  shouldRetry(statusCode: number, attempt: number): boolean {
    return attempt < this.maxRetries && this.retryOnStatus.has(statusCode);
  }

  /** Check if error should be retried */
  shouldRetryError(error: Error, attempt: number): boolean {
    if (attempt >= this.maxRetries) {
      return false;
    }
    // Retry on network errors
    return (
      error.name === 'NetworkError' ||
      error.message.includes('fetch') ||
      error.message.includes('network')
    );
  }

  /** Calculate delay for next retry */
  getDelay(attempt: number): number {
    const exponentialDelay = this.baseDelay * Math.pow(2, attempt);
    const cappedDelay = Math.min(exponentialDelay, this.maxDelay);
    const jitterAmount = cappedDelay * this.jitter * Math.random();
    return cappedDelay + jitterAmount;
  }

  /** Sleep for the calculated delay */
  async sleep(attempt: number): Promise<void> {
    const delay = this.getDelay(attempt);
    await new Promise((resolve) => setTimeout(resolve, delay));
  }
}

/** Session scope validator */
export class ScopeValidator {
  private readonly scope: SessionScope;
  private operationCount = 0;

  constructor(scope: SessionScope) {
    this.scope = scope;
  }

  /** Check if operation is allowed */
  isOperationAllowed(operation: string): boolean {
    if (!this.scope.allowedOperations) {
      return true;
    }
    return this.scope.allowedOperations.includes(operation);
  }

  /** Check if key access is allowed */
  isKeyAllowed(keyId: string): boolean {
    if (!this.scope.allowedKeys) {
      return true;
    }
    return this.scope.allowedKeys.includes(keyId);
  }

  /** Check if more operations are allowed */
  canPerformOperation(): boolean {
    if (this.scope.maxOperations === undefined) {
      return true;
    }
    return this.operationCount < this.scope.maxOperations;
  }

  /** Increment operation count */
  incrementOperationCount(): void {
    this.operationCount++;
  }

  /** Get remaining operations */
  getRemainingOperations(): number | undefined {
    if (this.scope.maxOperations === undefined) {
      return undefined;
    }
    return Math.max(0, this.scope.maxOperations - this.operationCount);
  }
}
