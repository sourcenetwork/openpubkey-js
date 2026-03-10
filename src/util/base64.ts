/**
 * Base64 URL encoding/decoding utilities for JWT tokens
 * Browser and Node.js compatible
 */

/**
 * Converts a Uint8Array to base64 string
 */
function uint8ArrayToBase64(bytes: Uint8Array): string {
  // Use Node.js Buffer if available, otherwise browser btoa
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }

  // Browser: convert bytes to string, then use btoa
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Converts a base64 string to Uint8Array
 */
function base64ToUint8Array(base64: string): Uint8Array {
  // Use Node.js Buffer if available, otherwise browser atob
  if (typeof Buffer !== 'undefined') {
    const buf = Buffer.from(base64, 'base64');
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  // Browser: use atob, then convert string to bytes
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encodes a Uint8Array to base64url format (no padding) for JWT usage
 * @param decoded - The data to encode
 * @returns The base64url encoded string as Uint8Array
 */
export function base64EncodeForJWT(decoded: Uint8Array): Uint8Array {
  const base64 = uint8ArrayToBase64(decoded);
  const base64url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return new TextEncoder().encode(base64url);
}

/**
 * Encodes a string or Uint8Array to base64url format (no padding) for JWT usage
 * @param input - The data to encode (string or Uint8Array)
 * @returns The base64url encoded string
 */
export function base64UrlEncode(input: string | Uint8Array): string {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const base64 = uint8ArrayToBase64(bytes);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Decodes a base64url formatted string (no padding) for JWT usage
 * @param encoded - The base64url encoded data
 * @returns The decoded Uint8Array
 */
export function base64DecodeForJWT(encoded: Uint8Array | string): Uint8Array {
  const encodedStr = typeof encoded === 'string' ? encoded : new TextDecoder().decode(encoded);
  let base64 = encodedStr.replace(/-/g, '+').replace(/_/g, '/');
  const padding = base64.length % 4;
  if (padding > 0) {
    base64 += '='.repeat(4 - padding);
  }
  return base64ToUint8Array(base64);
}
