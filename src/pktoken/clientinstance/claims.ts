import * as jose from 'jose';
import { b64SHA3_256, randomBytes, randomHex } from '../../util/crypto.js';
import { base64DecodeForJWT, base64UrlEncode } from '../../util/base64.js';
import { jsonStringifySorted } from '../../util/json.js';
import { splitCompact } from '../../oidc/oidc.js';

declare const window: { crypto?: { subtle?: SubtleCrypto } } | undefined;

const isBrowser = typeof window !== 'undefined' && typeof window.crypto !== 'undefined';

/**
 * Client Instance Claims (CIC) - relates to a single key pair
 * Works in both Node.js and browser environments
 */
export class Claims {
  private publicKey: jose.JWK;
  private protected: Record<string, unknown>;

  constructor(publicKey: jose.JWK, protectedClaims: Record<string, unknown>) {
    this.publicKey = publicKey;
    this.protected = protectedClaims;
  }

  /**
   * Creates new Client Instance Claims
   */
  static async newClaims(
    publicKey: jose.KeyLike,
    claims: Record<string, unknown> = {}
  ): Promise<Claims> {
    let jwk: jose.JWK;
    if (isBrowser && 'algorithm' in (publicKey as CryptoKey)) {
      const cryptoKey = publicKey as CryptoKey;
      jwk = (await crypto.subtle.exportKey('jwk', cryptoKey)) as jose.JWK;
      if (!jwk.alg) {
        const algName = cryptoKey.algorithm.name;
        if (algName === 'ECDSA') {
          jwk.alg = 'ES256';
        } else if (algName === 'RSASSA-PKCS1-v1_5') {
          jwk.alg = 'RS256';
        } else {
          throw new Error('Unable to determine algorithm from CryptoKey');
        }
      }
      const { key_ops: _keyOps, ...cleanJwk } = jwk;
      jwk = cleanJwk;
    } else {
      jwk = await jose.exportJWK(publicKey);
      if (!jwk.alg) {
        throw new Error('User JWK requires algorithm to be set');
      }
    }
    const reserved = ['alg', 'upk', 'rz', 'typ'];
    for (const r of reserved) {
      if (r in claims) {
        throw new Error(`Use of reserved header name: ${r} in additional headers`);
      }
    }
    const rz = isBrowser ? randomHex(32) : generateRand();
    const protectedClaims = {
      ...claims,
      typ: 'CIC',
      alg: jwk.alg,
      upk: jwk,
      rz: rz,
    };
    return new Claims(jwk, protectedClaims);
  }

  /**
   * Parses Claims from a protected header map
   */
  static parseClaims(protectedMap: Record<string, unknown>): Claims {
    if (!('rz' in protectedMap)) {
      throw new Error('Missing required "rz" claim');
    }
    if (!('upk' in protectedMap)) {
      throw new Error('Missing required "upk" claim');
    }
    const upk = protectedMap.upk as jose.JWK;
    if (!('alg' in protectedMap)) {
      throw new Error('Missing required "alg" claim');
    }
    const alg = protectedMap.alg;
    if (alg !== upk.alg) {
      throw new Error('Provided "alg" value different from algorithm provided in "upk" JWK');
    }
    return new Claims(upk, protectedMap);
  }

  /**
   * Gets the public key
   */
  getPublicKey(): jose.JWK {
    return this.publicKey;
  }

  /**
   * Gets the key algorithm
   */
  getKeyAlgorithm(): string {
    return this.publicKey.alg || '';
  }

  /**
   * Gets the protected claims
   */
  getProtected(): Record<string, unknown> {
    return this.protected;
  }

  /**
   * Returns a base64url encoded hash of all client instance claims
   */
  async hash(): Promise<Uint8Array> {
    const buf = jsonStringifySorted(this.protected);
    return await b64SHA3_256(new TextEncoder().encode(buf));
  }

  /**
   * Signs the payload of a token with the protected headers defined by the CIC
   */
  async sign(
    signer: jose.KeyLike,
    _algorithm: string,
    token: Uint8Array
  ): Promise<Uint8Array> {
    const [, payloadEncoded] = splitCompact(token);
    const payloadDecoded = base64DecodeForJWT(payloadEncoded);
    if (isBrowser && 'algorithm' in (signer as CryptoKey)) {
      const cryptoKey = signer as CryptoKey;
      const header = this.protected;
      const payload = JSON.parse(new TextDecoder().decode(payloadDecoded));
      const headerB64 = base64UrlEncode(JSON.stringify(header));
      const payloadB64 = base64UrlEncode(JSON.stringify(payload));
      const signingInput = `${headerB64}.${payloadB64}`;
      const signingInputBytes = new TextEncoder().encode(signingInput);
      const signatureBytes = await crypto.subtle.sign(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        cryptoKey,
        signingInputBytes
      );
      const signatureB64 = base64UrlEncode(new Uint8Array(signatureBytes));
      const jwt = `${signingInput}.${signatureB64}`;
      return new TextEncoder().encode(jwt);
    } else {
      const jwt = await new jose.SignJWT(JSON.parse(new TextDecoder().decode(payloadDecoded)))
        .setProtectedHeader(this.protected as jose.JWTHeaderParameters)
        .sign(signer);
      return new TextEncoder().encode(jwt);
    }
  }
}

/**
 * Generates a random hex string (256 bits) - Node.js version
 */
function generateRand(): string {
  const bytes = randomBytes(32);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
