/**
 * HSM Client Tests
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { createClient, HsmClient } from '../src/client';
import { fromBase64, isBase64, toBase64 } from '../src/crypto';
import { AuthenticationError, NetworkError, NotFoundError, RateLimitError } from '../src/errors';

describe('HsmClient', () => {
  let client: HsmClient;

  beforeEach(() => {
    client = createClient({
      baseUrl: 'https://hsm.example.com',
      sessionId: 'test-session',
      sessionToken: 'test-token',
    });
  });

  describe('createClient', () => {
    it('should create client with config', () => {
      expect(client).toBeInstanceOf(HsmClient);
    });

    it('should strip trailing slash from baseUrl', () => {
      const trailingSlashClient = createClient({
        baseUrl: 'https://hsm.example.com/',
      });
      expect(trailingSlashClient).toBeInstanceOf(HsmClient);
    });
  });

  describe('authentication', () => {
    it('should report authenticated when credentials set', () => {
      expect(client.isAuthenticated()).toBe(true);
    });

    it('should report not authenticated when no credentials', () => {
      const anonymousClient = createClient({
        baseUrl: 'https://hsm.example.com',
      });
      expect(anonymousClient.isAuthenticated()).toBe(false);
    });

    it('should clear credentials', () => {
      client.clearCredentials();
      expect(client.isAuthenticated()).toBe(false);
    });

    it('should set new credentials', () => {
      client.clearCredentials();
      client.setCredentials('new-session', 'new-token');
      expect(client.isAuthenticated()).toBe(true);
    });
  });

  describe('circuit breaker', () => {
    it('should start closed', () => {
      expect(client.getCircuitState()).toBe('closed');
    });

    it('should reset circuit breaker', () => {
      client.resetCircuitBreaker();
      expect(client.getCircuitState()).toBe('closed');
    });
  });

  describe('operation count', () => {
    it('should start at zero', () => {
      expect(client.getOperationCount()).toBe(0);
    });
  });
});

describe('Crypto Utilities', () => {
  describe('toBase64', () => {
    it('should encode bytes to base64', () => {
      const data = new Uint8Array([72, 101, 108, 108, 111]);
      expect(toBase64(data)).toBe('SGVsbG8=');
    });

    it('should encode string to base64', () => {
      expect(toBase64('Hello')).toBe('SGVsbG8=');
    });

    it('should return base64 string as-is', () => {
      expect(toBase64('SGVsbG8=')).toBe('SGVsbG8=');
    });
  });

  describe('fromBase64', () => {
    it('should decode base64 to bytes', () => {
      const bytes = fromBase64('SGVsbG8=');
      expect(Array.from(bytes)).toEqual([72, 101, 108, 108, 111]);
    });
  });

  describe('isBase64', () => {
    it('should return true for valid base64', () => {
      expect(isBase64('SGVsbG8=')).toBe(true);
      expect(isBase64('')).toBe(true);
      expect(isBase64('YWJj')).toBe(true);
    });

    it('should return false for invalid base64', () => {
      expect(isBase64('Hello')).toBe(false);
      expect(isBase64('abc')).toBe(false);
    });
  });
});

describe('Error Classes', () => {
  it('should create AuthenticationError', () => {
    const error = new AuthenticationError('Invalid credentials');
    expect(error.name).toBe('AuthenticationError');
    expect(error.statusCode).toBe(401);
    expect(error.code).toBe('AUTHENTICATION_FAILED');
  });

  it('should create NotFoundError', () => {
    const error = new NotFoundError('Key', 'key-123');
    expect(error.name).toBe('NotFoundError');
    expect(error.message).toBe('Key not found: key-123');
    expect(error.statusCode).toBe(404);
  });

  it('should create RateLimitError with retry after', () => {
    const error = new RateLimitError('Too many requests', { retryAfter: 60 });
    expect(error.name).toBe('RateLimitError');
    expect(error.retryAfter).toBe(60);
    expect(error.statusCode).toBe(429);
  });

  it('should create NetworkError', () => {
    const cause = new Error('Connection refused');
    const error = new NetworkError('Network error', { cause });
    expect(error.name).toBe('NetworkError');
    expect(error.cause).toBe(cause);
  });
});
