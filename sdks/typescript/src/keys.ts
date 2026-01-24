/**
 * HSM Key Management
 *
 * High-level key management operations.
 */

import type {
  GenerateKeyRequest,
  GenerateKeyResponse,
  KeyMetadata,
  ListKeysResponse,
  ListKeysOptions,
  KeyAlgorithm,
  KeyPurpose,
} from './types';

/** Key management class for convenient key operations */
export class KeyManager {
  private readonly client: KeyManagerClient;

  constructor(client: KeyManagerClient) {
    this.client = client;
  }

  /**
   * Generate a new key with simplified options
   */
  async generate(options: {
    algorithm: KeyAlgorithm;
    purpose?: KeyPurpose;
    id?: string;
    namespace?: string;
    labels?: Record<string, string>;
  }): Promise<GenerateKeyResponse> {
    const request: GenerateKeyRequest = {
      key_id: options.id,
      algorithm: options.algorithm,
      purpose: options.purpose ?? 'GENERAL',
      namespace: options.namespace,
      labels: options.labels,
    };
    return this.client.generateKey(request);
  }

  /**
   * Generate an Ed25519 signing key
   */
  async generateEd25519(options?: {
    id?: string;
    namespace?: string;
    labels?: Record<string, string>;
  }): Promise<GenerateKeyResponse> {
    return this.generate({
      algorithm: 'ED25519',
      purpose: 'SIGN',
      ...options,
    });
  }

  /**
   * Generate an ECDSA P-256 key
   */
  async generateEcdsaP256(options?: {
    id?: string;
    namespace?: string;
    labels?: Record<string, string>;
    purpose?: KeyPurpose;
  }): Promise<GenerateKeyResponse> {
    return this.generate({
      algorithm: 'ECDSA_P256',
      purpose: options?.purpose ?? 'SIGN',
      ...options,
    });
  }

  /**
   * Generate an ECDSA P-384 key
   */
  async generateEcdsaP384(options?: {
    id?: string;
    namespace?: string;
    labels?: Record<string, string>;
    purpose?: KeyPurpose;
  }): Promise<GenerateKeyResponse> {
    return this.generate({
      algorithm: 'ECDSA_P384',
      purpose: options?.purpose ?? 'SIGN',
      ...options,
    });
  }

  /**
   * Generate an RSA key
   */
  async generateRsa(options: {
    size: 2048 | 3072 | 4096;
    id?: string;
    namespace?: string;
    labels?: Record<string, string>;
    purpose?: KeyPurpose;
  }): Promise<GenerateKeyResponse> {
    const algorithmMap: Record<number, KeyAlgorithm> = {
      2048: 'RSA2048',
      3072: 'RSA3072',
      4096: 'RSA4096',
    };
    return this.generate({
      algorithm: algorithmMap[options.size],
      purpose: options.purpose ?? 'SIGN',
      ...options,
    });
  }

  /**
   * Generate an AES encryption key
   */
  async generateAes(options: {
    size: 128 | 256;
    id?: string;
    namespace?: string;
    labels?: Record<string, string>;
  }): Promise<GenerateKeyResponse> {
    const algorithmMap: Record<number, KeyAlgorithm> = {
      128: 'AES128',
      256: 'AES256',
    };
    return this.generate({
      algorithm: algorithmMap[options.size],
      purpose: 'ENCRYPT',
      ...options,
    });
  }

  /**
   * Get key metadata
   */
  async get(keyId: string): Promise<KeyMetadata> {
    return this.client.getKey(keyId);
  }

  /**
   * List all keys
   */
  async list(options?: ListKeysOptions): Promise<ListKeysResponse> {
    return this.client.listKeys(options);
  }

  /**
   * List all keys with automatic pagination
   */
  async *listAll(options?: Omit<ListKeysOptions, 'cursor'>): AsyncGenerator<KeyMetadata> {
    let cursor: string | undefined;
    do {
      const response = await this.client.listKeys({ ...options, cursor });
      for (const key of response.keys) {
        yield key;
      }
      cursor = response.next_cursor;
    } while (cursor);
  }

  /**
   * Delete a key
   */
  async delete(keyId: string): Promise<void> {
    return this.client.deleteKey(keyId);
  }

  /**
   * Check if a key exists
   */
  async exists(keyId: string): Promise<boolean> {
    try {
      await this.client.getKey(keyId);
      return true;
    } catch {
      return false;
    }
  }
}

/** Interface for key manager client operations */
export interface KeyManagerClient {
  generateKey(request: GenerateKeyRequest): Promise<GenerateKeyResponse>;
  getKey(keyId: string): Promise<KeyMetadata>;
  listKeys(options?: ListKeysOptions): Promise<ListKeysResponse>;
  deleteKey(keyId: string): Promise<void>;
}
