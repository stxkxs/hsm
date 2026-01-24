/**
 * HSM Crypto Helpers
 *
 * Utility functions for cryptographic operations.
 */

/**
 * Encode bytes to base64
 */
export function toBase64(data: Uint8Array | string): string {
  if (typeof data === 'string') {
    // Already base64 or text - assume text and encode
    if (isBase64(data)) {
      return data;
    }
    data = new TextEncoder().encode(data);
  }

  // Node.js environment
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(data).toString('base64');
  }

  // Browser environment
  let binary = '';
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary);
}

/**
 * Decode base64 to bytes
 */
export function fromBase64(data: string): Uint8Array {
  // Node.js environment
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(data, 'base64'));
  }

  // Browser environment
  const binary = atob(data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Check if string is valid base64
 */
export function isBase64(str: string): boolean {
  if (str.length === 0) return true;
  const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
  return base64Regex.test(str) && str.length % 4 === 0;
}

/**
 * Encode bytes to hex
 */
export function toHex(data: Uint8Array): string {
  return Array.from(data)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Decode hex to bytes
 */
export function fromHex(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.slice(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Normalize data to base64 for API requests
 */
export function normalizeToBase64(data: string | Uint8Array): string {
  if (typeof data === 'string') {
    // If already base64, return as-is
    if (isBase64(data)) {
      return data;
    }
    // Otherwise, encode as UTF-8 text
    return toBase64(new TextEncoder().encode(data));
  }
  return toBase64(data);
}

/**
 * Hash data using SHA-256 (browser-compatible)
 */
export async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;

  // Use Web Crypto API (available in both browser and Node.js 20+)
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
    return new Uint8Array(hashBuffer);
  }

  // Fallback for older Node.js
  if (typeof require !== 'undefined') {
    const cryptoModule = require('crypto');
    return new Uint8Array(cryptoModule.createHash('sha256').update(bytes).digest());
  }

  throw new Error('No crypto implementation available');
}

/**
 * Hash data using Keccak-256 (Ethereum)
 * Note: For full Ethereum support, use a dedicated library like ethers.js
 */
export async function keccak256(data: Uint8Array | string): Promise<Uint8Array> {
  // This is a placeholder - for production use, implement or import keccak256
  // For now, we'll use SHA-256 as a fallback with a warning
  console.warn('keccak256: Using SHA-256 as fallback. For Ethereum operations, use ethers.js or similar.');
  return sha256(data);
}

/**
 * Create a message hash for signing (pre-hash if needed)
 */
export async function createMessageHash(
  message: string | Uint8Array,
  algorithm: 'SHA-256' | 'SHA-384' | 'SHA-512' | 'KECCAK-256' = 'SHA-256'
): Promise<Uint8Array> {
  const bytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;

  if (algorithm === 'KECCAK-256') {
    return keccak256(bytes);
  }

  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const hashBuffer = await crypto.subtle.digest(algorithm, bytes);
    return new Uint8Array(hashBuffer);
  }

  if (typeof require !== 'undefined') {
    const cryptoModule = require('crypto');
    const nodeAlgorithm = algorithm.toLowerCase().replace('-', '');
    return new Uint8Array(cryptoModule.createHash(nodeAlgorithm).update(bytes).digest());
  }

  throw new Error('No crypto implementation available');
}

/**
 * Compare two byte arrays in constant time
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}

/**
 * Generate random bytes
 */
export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);

  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
    return bytes;
  }

  if (typeof require !== 'undefined') {
    const cryptoModule = require('crypto');
    return new Uint8Array(cryptoModule.randomBytes(length));
  }

  throw new Error('No crypto implementation available');
}

/**
 * Concatenate multiple byte arrays
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Split bytes at a given index
 */
export function splitBytes(data: Uint8Array, index: number): [Uint8Array, Uint8Array] {
  return [data.slice(0, index), data.slice(index)];
}

/**
 * Convert signature format from DER to raw (R || S)
 * Useful for Ethereum and other chains that expect raw format
 */
export function derToRaw(derSignature: Uint8Array): Uint8Array {
  // Simple DER parsing - for production, use a proper ASN.1 library
  // DER format: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s]

  if (derSignature[0] !== 0x30) {
    // Already in raw format or invalid
    return derSignature;
  }

  let offset = 2; // Skip 0x30 and length byte

  // Parse R
  if (derSignature[offset] !== 0x02) {
    throw new Error('Invalid DER signature');
  }
  offset++;
  const rLen = derSignature[offset];
  offset++;
  let r = derSignature.slice(offset, offset + rLen);
  offset += rLen;

  // Parse S
  if (derSignature[offset] !== 0x02) {
    throw new Error('Invalid DER signature');
  }
  offset++;
  const sLen = derSignature[offset];
  offset++;
  let s = derSignature.slice(offset, offset + sLen);

  // Remove leading zeros if present (DER encoding adds them for positive numbers)
  if (r[0] === 0x00 && r.length > 32) {
    r = r.slice(1);
  }
  if (s[0] === 0x00 && s.length > 32) {
    s = s.slice(1);
  }

  // Pad to 32 bytes each
  const rPadded = new Uint8Array(32);
  const sPadded = new Uint8Array(32);
  rPadded.set(r, 32 - r.length);
  sPadded.set(s, 32 - s.length);

  return concatBytes(rPadded, sPadded);
}

/**
 * Convert signature format from raw (R || S) to DER
 */
export function rawToDer(rawSignature: Uint8Array): Uint8Array {
  if (rawSignature.length !== 64) {
    // Might already be DER or invalid
    return rawSignature;
  }

  let r = rawSignature.slice(0, 32);
  let s = rawSignature.slice(32, 64);

  // Remove leading zeros
  while (r.length > 1 && r[0] === 0x00 && !(r[1] & 0x80)) {
    r = r.slice(1);
  }
  while (s.length > 1 && s[0] === 0x00 && !(s[1] & 0x80)) {
    s = s.slice(1);
  }

  // Add leading zero if high bit is set (to ensure positive integer)
  if (r[0] & 0x80) {
    r = concatBytes(new Uint8Array([0x00]), r);
  }
  if (s[0] & 0x80) {
    s = concatBytes(new Uint8Array([0x00]), s);
  }

  const totalLen = 4 + r.length + s.length; // 2 bytes for each INTEGER header

  return new Uint8Array([
    0x30, // SEQUENCE
    totalLen,
    0x02, // INTEGER (R)
    r.length,
    ...r,
    0x02, // INTEGER (S)
    s.length,
    ...s,
  ]);
}
