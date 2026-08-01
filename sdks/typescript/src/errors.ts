/**
 * HSM Client Errors
 *
 * Custom error types for the HSM TypeScript SDK.
 */

/** Base error class for HSM errors */
export class HsmError extends Error {
  /** HTTP status code (if applicable) */
  public readonly statusCode?: number;
  /** Error code from server */
  public readonly code?: string;
  /** Additional error details */
  public readonly details?: Record<string, unknown>;

  constructor(
    message: string,
    options?: {
      statusCode?: number;
      code?: string;
      details?: Record<string, unknown>;
      cause?: Error;
    }
  ) {
    super(message, { cause: options?.cause });
    this.name = 'HsmError';
    this.statusCode = options?.statusCode;
    this.code = options?.code;
    this.details = options?.details;
  }
}

/** Error when authentication fails */
export class AuthenticationError extends HsmError {
  constructor(message: string, options?: { cause?: Error }) {
    super(message, { statusCode: 401, code: 'AUTHENTICATION_FAILED', ...options });
    this.name = 'AuthenticationError';
  }
}

/** Error when authorization fails */
export class AuthorizationError extends HsmError {
  constructor(message: string, options?: { cause?: Error }) {
    super(message, { statusCode: 403, code: 'AUTHORIZATION_FAILED', ...options });
    this.name = 'AuthorizationError';
  }
}

/** Error when a resource is not found */
export class NotFoundError extends HsmError {
  constructor(resource: string, id: string, options?: { cause?: Error }) {
    super(`${resource} not found: ${id}`, { statusCode: 404, code: 'NOT_FOUND', ...options });
    this.name = 'NotFoundError';
  }
}

/** Error when input validation fails */
export class ValidationError extends HsmError {
  /** Field that failed validation */
  public readonly field?: string;

  constructor(message: string, options?: { field?: string; cause?: Error }) {
    super(message, { statusCode: 400, code: 'VALIDATION_ERROR' });
    this.name = 'ValidationError';
    this.field = options?.field;
  }
}

/** Error when rate limit is exceeded */
export class RateLimitError extends HsmError {
  /** When the rate limit resets */
  public readonly retryAfter?: number;

  constructor(message: string, options?: { retryAfter?: number; cause?: Error }) {
    super(message, { statusCode: 429, code: 'RATE_LIMIT_EXCEEDED', ...options });
    this.name = 'RateLimitError';
    this.retryAfter = options?.retryAfter;
  }
}

/** Error when a network request fails */
export class NetworkError extends HsmError {
  constructor(message: string, options?: { cause?: Error }) {
    super(message, { code: 'NETWORK_ERROR', ...options });
    this.name = 'NetworkError';
  }
}

/** Error when request times out */
export class TimeoutError extends HsmError {
  constructor(message: string = 'Request timed out', options?: { cause?: Error }) {
    super(message, { code: 'TIMEOUT', ...options });
    this.name = 'TimeoutError';
  }
}

/** Error when server returns an error */
export class ServerError extends HsmError {
  constructor(message: string, statusCode: number, options?: { cause?: Error }) {
    super(message, { statusCode, code: 'SERVER_ERROR', ...options });
    this.name = 'ServerError';
  }
}

/** Error when a cryptographic operation fails */
export class CryptoError extends HsmError {
  constructor(message: string, options?: { cause?: Error }) {
    super(message, { code: 'CRYPTO_ERROR', ...options });
    this.name = 'CryptoError';
  }
}

/** Error when session is invalid or expired */
export class SessionError extends HsmError {
  constructor(message: string, options?: { cause?: Error }) {
    super(message, { statusCode: 401, code: 'SESSION_ERROR', ...options });
    this.name = 'SessionError';
  }
}

/**
 * Parse an error response from the server
 */
export function parseErrorResponse(statusCode: number, body: unknown): HsmError {
  const message =
    typeof body === 'object' && body !== null && 'message' in body
      ? String((body as { message: unknown }).message)
      : 'Unknown error';

  const code =
    typeof body === 'object' && body !== null && 'code' in body
      ? String((body as { code: unknown }).code)
      : undefined;

  switch (statusCode) {
    case 400:
      return new ValidationError(message);
    case 401:
      return new AuthenticationError(message);
    case 403:
      return new AuthorizationError(message);
    case 404:
      return new NotFoundError('Resource', 'unknown');
    case 429: {
      const retryAfter =
        typeof body === 'object' && body !== null && 'retry_after' in body
          ? Number((body as { retry_after: unknown }).retry_after)
          : undefined;
      return new RateLimitError(message, { retryAfter });
    }
    default:
      if (statusCode >= 500) {
        return new ServerError(message, statusCode);
      }
      return new HsmError(message, { statusCode, code });
  }
}
