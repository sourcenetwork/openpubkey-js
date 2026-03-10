import * as crypto from 'crypto';
import * as jose from 'jose';
import { base64EncodeForJWT, base64DecodeForJWT } from '../util/base64.js';
import { bytesEqual } from '../util/bytes.js';

// RSA constants
const RSA_EXPONENT_65537 = 65537n;
const SHA256_HASH_LENGTH = 32;

/**
 * GQ256 signature algorithm constant
 */
export const GQ256 = 'GQ256';

/**
 * Options for GQ signing with extra claims
 */
export interface GQSignOptions {
  extraClaims?: Record<string, string>;
}

/**
 * Helper to add extra claims to GQ sign options
 */
export function withExtraClaim(key: string, value: string): (opts: GQSignOptions) => void {
  return (opts: GQSignOptions) => {
    if (!opts.extraClaims) {
      opts.extraClaims = {};
    }
    opts.extraClaims[key] = value;
  };
}

/**
 * GQ256SignJWT takes an RSA public key and signed JWT and computes a GQ1 signature
 * on the JWT. It returns a JWT whose RSA signature has been replaced by
 * the GQ signature.
 *
 * Note: This is a TypeScript implementation of GQ signatures. While it implements
 * the GQ1 signature scheme, it may not have the same constant-time guarantees
 * as the Go implementation.
 *
 * @param rsaPublicKey - The RSA public key (as JWK)
 * @param jwt - The signed JWT token
 * @param options - Optional extra claims to include in the GQ signature
 * @returns The GQ-signed JWT
 */
export async function gq256SignJWT(
  rsaPublicKey: jose.JWK,
  jwt: Uint8Array,
  options?: GQSignOptions
): Promise<Uint8Array> {
  // Verify the JWT is signed with RS256 using the provided public key
  const jwtStr = new TextDecoder().decode(jwt);
  const publicKey = await jose.importJWK(rsaPublicKey, 'RS256');
  try {
    await jose.compactVerify(jwtStr, publicKey);
  } catch (err) {
    throw new Error(`Incorrect public key supplied when GQ signing JWT: ${err}`);
  }
  // Create a GQ signer/verifier
  const sv = await new256SignerVerifier(rsaPublicKey);
  // Sign the JWT with GQ
  const gqJWT = await sv.signJWT(jwt, options);
  return gqJWT;
}

/**
 * GQ256VerifyJWT verifies a GQ1 signature over a GQ signed JWT
 *
 * @param rsaPublicKey - The RSA public key (as JWK)
 * @param gqToken - The GQ-signed JWT token
 * @returns True if the signature is valid
 */
export async function gq256VerifyJWT(rsaPublicKey: jose.JWK, gqToken: Uint8Array): Promise<boolean> {
  const sv = await new256SignerVerifier(rsaPublicKey);
  return sv.verifyJWT(gqToken);
}

/**
 * Signer interface for creating GQ1 signatures
 */
export interface Signer {
  /**
   * Sign creates a GQ1 signature over the given message with the given GQ1 private number.
   */
  sign(privateNum: Uint8Array, message: Uint8Array): Promise<Uint8Array>;

  /**
   * SignJWT creates a GQ1 signature over the JWT token's header/payload with a GQ1 private number
   * derived from the JWT signature.
   */
  signJWT(jwt: Uint8Array, options?: GQSignOptions): Promise<Uint8Array>;
}

/**
 * Verifier interface for verifying GQ1 signatures
 */
export interface Verifier {
  /**
   * Verify verifies a GQ1 signature over a message, using the public identity of the signer.
   */
  verify(signature: Uint8Array, identity: Uint8Array, message: Uint8Array): boolean;

  /**
   * Compatible with signJWT, this function verifies the GQ1 signature of the presented JSON Web Token.
   */
  verifyJWT(jwt: Uint8Array): boolean;
}

/**
 * SignerVerifier combines the Signer and Verifier interfaces
 */
export interface SignerVerifier extends Signer, Verifier { }

/**
 * Internal signer/verifier implementation
 */
class SignerVerifierImpl implements SignerVerifier {
  private n: bigint; // RSA public modulus
  private v: bigint; // RSA public exponent
  private nBytes: number; // Length of n in bytes
  private vBytes: number; // Length of v in bytes
  private t: number; // Signature length parameter

  constructor(n: bigint, v: bigint, nBytes: number, vBytes: number, t: number) {
    this.n = n;
    this.v = v;
    this.nBytes = nBytes;
    this.vBytes = vBytes;
    this.t = t;
  }

  async sign(privateNum: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
    const Q = bytesToBigInt(privateNum);
    // Select t random numbers
    const r: bigint[] = [];
    for (let i = 0; i < this.t; i++) {
      r.push(await randomBigInt(this.n));
    }
    // Calculate test number W
    const W: number[] = [];
    for (let i = 0; i < this.t; i++) {
      const W_i = modPow(r[i], this.v, this.n);
      const bytes = bigIntToBytes(W_i, this.nBytes);
      W.push(...bytes);
    }
    // Calculate question number R
    const R = await shake256(this.t * this.vBytes, new Uint8Array(W), message);
    // Split R into t numbers each consisting of vBytes bytes
    const Rs: bigint[] = [];
    for (let i = 0; i < this.t; i++) {
      Rs.push(bytesToBigInt(R.slice(i * this.vBytes, (i + 1) * this.vBytes)));
    }
    // Calculate witness number S
    const S: number[] = [];
    for (let i = 0; i < this.t; i++) {
      const S_i = (modPow(Q, Rs[i], this.n) * r[i]) % this.n;
      const bytes = bigIntToBytes(S_i, this.nBytes);
      S.push(...bytes);
    }
    // Proof is combination of R and S
    return encodeProof(R, new Uint8Array(S));
  }

  async signJWT(jwt: Uint8Array, options?: GQSignOptions): Promise<Uint8Array> {
    const opts = options || {};
    // Ensure reserved header names aren't used
    const reserved = ['alg', 'typ', 'kid'];
    for (const key of reserved) {
      if (opts.extraClaims && key in opts.extraClaims) {
        throw new Error(`Use of reserved header name: ${key}`);
      }
    }
    // Split JWT into components
    const jwtStr = new TextDecoder().decode(jwt);
    const parts = jwtStr.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }
    const origHeaders = parts[0];
    const payload = parts[1];
    const signature = parts[2];
    const signingPayload = new TextEncoder().encode(`${origHeaders}.${payload}`);
    // Create new GQ headers
    const headers: Record<string, unknown> = {
      alg: GQ256,
      typ: 'JWT',
      kid: origHeaders,
    };
    // Add extra claims
    if (opts.extraClaims) {
      Object.assign(headers, opts.extraClaims);
    }
    const headersJSON = JSON.stringify(headers);
    const headersEnc = new TextDecoder().decode(base64EncodeForJWT(new TextEncoder().encode(headersJSON)));
    // Decode the RSA signature
    const decodedSig = base64DecodeForJWT(signature);
    // GQ1 private number (Q) is inverse of RSA signature mod n
    const privateNum = modInverse(bytesToBigInt(decodedSig), this.n);
    const privateBytes = bigIntToBytes(privateNum, this.nBytes);
    // Sign with GQ
    const gqSig = await this.sign(privateBytes, signingPayload);
    // Create new GQ-signed token
    const gqToken = `${headersEnc}.${payload}.${new TextDecoder().decode(gqSig)}`;
    return new TextEncoder().encode(gqToken);
  }

  verify(proof: Uint8Array, identity: Uint8Array, message: Uint8Array): boolean {
    try {
      // Decode proof
      const { R, S } = decodeProof(proof, this.t, this.vBytes, this.nBytes);
      // Create public number G
      const paddedIdentity = encodePKCS1v15(this.nBytes, identity);
      const G = bytesToBigInt(paddedIdentity);
      // Parse signature numbers and recalculate test number W*
      const Rs: bigint[] = [];
      for (let i = 0; i < this.t; i++) {
        Rs.push(bytesToBigInt(R.slice(i * this.vBytes, (i + 1) * this.vBytes)));
      }
      const Ss: bigint[] = [];
      for (let i = 0; i < this.t; i++) {
        const s_i = bytesToBigInt(S.slice(i * this.nBytes, (i + 1) * this.nBytes));
        // Reject if S_i = 0 or >= n
        if (s_i === 0n || s_i >= this.n) {
          return false;
        }
        Ss.push(s_i);
      }
      // Recalculate test number W*
      const Wstar: number[] = [];
      for (let i = 0; i < this.t; i++) {
        const l = modPow(Ss[i], this.v, this.n);
        const r = modPow(G, Rs[i], this.n);
        const Wstar_i = (l * r) % this.n;
        const bytes = bigIntToBytes(Wstar_i, this.nBytes);
        Wstar.push(...bytes);
      }
      // Recalculate question number R*
      const Rstar = shake256Sync(this.t * this.vBytes, new Uint8Array(Wstar), message);
      // Accept or reject
      return bytesEqual(R, Rstar);
    } catch {
      return false;
    }
  }

  verifyJWT(jwt: Uint8Array): boolean {
    try {
      const jwtStr = new TextDecoder().decode(jwt);
      const parts = jwtStr.split('.');
      if (parts.length !== 3) {
        return false;
      }
      // Extract original headers from kid field
      const headersJSON = base64DecodeForJWT(parts[0]);
      const headers = JSON.parse(new TextDecoder().decode(headersJSON)) as Record<string, unknown>;
      if (headers.alg !== GQ256) {
        return false;
      }
      const origHeaders = headers.kid as string;
      const payload = parts[1];
      const signature = parts[2];
      const signingPayload = new TextEncoder().encode(`${origHeaders}.${payload}`);
      return this.verify(new TextEncoder().encode(signature), signingPayload, signingPayload);
    } catch {
      return false;
    }
  }
}

/**
 * Creates a new SignerVerifier specifically for GQ256 (security parameter is 256)
 */
export async function new256SignerVerifier(publicKey: jose.JWK): Promise<SignerVerifier> {
  return newSignerVerifier(publicKey, 256);
}

/**
 * Creates a new SignerVerifier from an RSA public key
 *
 * @param publicKey - RSA public key as JWK
 * @param securityParameter - Security level in bits (256 recommended)
 */
export async function newSignerVerifier(
  publicKey: jose.JWK,
  securityParameter: number
): Promise<SignerVerifier> {
  if (!publicKey.n || !publicKey.e) {
    throw new Error('Invalid RSA public key: missing n or e');
  }
  // Decode n and e from base64url
  const nBytes = base64DecodeForJWT(publicKey.n);
  const eBytes = base64DecodeForJWT(publicKey.e);
  const n = bytesToBigInt(nBytes);
  const v = bytesToBigInt(eBytes);
  if (v !== RSA_EXPONENT_65537) {
    throw new Error(`Only RSA exponent 65537 is currently supported, got: ${v}`);
  }
  const nByteLen = nBytes.length;
  const vBitLen = v.toString(2).length - 1;
  const vByteLen = Math.ceil(vBitLen / 8);
  const t = Math.floor(securityParameter / (vByteLen * 8));
  return new SignerVerifierImpl(n, v, nByteLen, vByteLen, t);
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus === 1n) return 0n;
  let result = 1n;
  base = base % modulus;
  while (exponent > 0n) {
    if (exponent % 2n === 1n) {
      result = (result * base) % modulus;
    }
    exponent = exponent >> 1n;
    base = (base * base) % modulus;
  }
  return result;
}

function modInverse(a: bigint, m: bigint): bigint {
  const original = m;
  let x = 0n;
  let y = 1n;
  while (a > 1n) {
    const q = a / m;
    let t = m;
    m = a % m;
    a = t;
    t = x;
    x = y - q * x;
    y = t;
  }
  if (y < 0n) {
    y += original;
  }
  return y;
}

async function randomBigInt(max: bigint): Promise<bigint> {
  const byteLen = Math.ceil(max.toString(16).length / 2);
  const randomBytes = crypto.randomBytes(byteLen);
  let result = bytesToBigInt(randomBytes);
  while (result >= max) {
    const newRandom = crypto.randomBytes(byteLen);
    result = bytesToBigInt(newRandom);
  }
  return result;
}

async function shake256(byteCount: number, ...data: Uint8Array[]): Promise<Uint8Array> {
  // Node.js crypto doesn't have SHAKE256, so we'll use a workaround with SHAKE256 if available
  // or fall back to repeated SHA3-256
  const hash = crypto.createHash('shake256', { outputLength: byteCount });
  for (const d of data) {
    hash.update(d);
  }
  return new Uint8Array(hash.digest());
}

function shake256Sync(byteCount: number, ...data: Uint8Array[]): Uint8Array {
  const hash = crypto.createHash('shake256', { outputLength: byteCount });
  for (const d of data) {
    hash.update(d);
  }
  return new Uint8Array(hash.digest());
}

function encodeProof(R: Uint8Array, S: Uint8Array): Uint8Array {
  const combined = new Uint8Array(R.length + S.length);
  combined.set(R, 0);
  combined.set(S, R.length);
  const encoded = base64EncodeForJWT(combined);
  return encoded;
}

function decodeProof(
  proof: Uint8Array,
  t: number,
  vBytes: number,
  nBytes: number
): { R: Uint8Array; S: Uint8Array } {
  const bin = base64DecodeForJWT(proof);
  const rSize = vBytes * t;
  const sSize = nBytes * t;
  if (bin.length !== rSize + sSize) {
    throw new Error('Proof is not the correct size');
  }
  const R = bin.slice(0, rSize);
  const S = bin.slice(rSize);
  return { R, S };
}

function encodePKCS1v15(k: number, data: Uint8Array): Uint8Array {
  // Hardcoded SHA-256 prefix from PKCS#1 v1.5
  const prefix = new Uint8Array([
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04,
    0x20,
  ]);
  const tLen = prefix.length + SHA256_HASH_LENGTH;
  // EM = 0x00 || 0x01 || PS || 0x00 || T
  const em = new Uint8Array(k);
  em[1] = 0x01;
  // Fill with 0xff padding
  for (let i = 2; i < k - tLen - 1; i++) {
    em[i] = 0xff;
  }
  // Copy prefix
  em.set(prefix, k - tLen);
  // Hash data with SHA-256
  const hash = crypto.createHash('sha256');
  hash.update(data);
  const hashed = hash.digest();
  // Copy hash
  em.set(hashed, k - SHA256_HASH_LENGTH);
  return em;
}

/**
 * Extracts original JWT headers from a GQ-signed JWT
 */
export function originalJWTHeaders(jwt: Uint8Array): Uint8Array {
  const jwtStr = new TextDecoder().decode(jwt);
  const parts = jwtStr.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }
  const headersJSON = base64DecodeForJWT(parts[0]);
  const headers = JSON.parse(new TextDecoder().decode(headersJSON)) as Record<string, unknown>;
  if (headers.alg !== GQ256) {
    throw new Error(`Expected GQ256 alg, got ${headers.alg}`);
  }
  const origHeaders = headers.kid as string;
  return new TextEncoder().encode(origHeaders);
}
