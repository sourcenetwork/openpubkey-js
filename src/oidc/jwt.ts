import * as jose from 'jose';
import { parseJWTSegment, splitCompact } from './oidc.js';
import type { OidcClaims } from './oidc.js';

/**
 * JWT helper class for parsing and working with JWT tokens
 */
export class Jwt {
  private token: Uint8Array;
  private protected: Record<string, unknown>;
  private payload: Record<string, unknown>;
  private signature: Uint8Array;

  private constructor(
    token: Uint8Array,
    protectedHeader: Record<string, unknown>,
    payload: Record<string, unknown>,
    signature: Uint8Array
  ) {
    this.token = token;
    this.protected = protectedHeader;
    this.payload = payload;
    this.signature = signature;
  }

  /**
   * Creates a new JWT from a token
   * @param token - The JWT token bytes
   * @returns A new Jwt instance
   */
  static newJwt(token: Uint8Array): Jwt {
    const [protectedBytes, payloadBytes, signatureBytes] = splitCompact(token);
    const protectedHeader = parseJWTSegment<Record<string, unknown>>(protectedBytes);
    const payload = parseJWTSegment<Record<string, unknown>>(payloadBytes);
    return new Jwt(token, protectedHeader, payload, signatureBytes);
  }

  /**
   * Gets the protected header
   */
  getProtectedHeader(): Record<string, unknown> {
    return this.protected;
  }

  /**
   * Gets the payload
   */
  getPayload(): Record<string, unknown> {
    return this.payload;
  }

  /**
   * Gets the payload as OIDC claims
   */
  getClaims(): Partial<OidcClaims> {
    return {
      iss: this.payload.iss as string,
      sub: this.payload.sub as string,
      aud: this.payload.aud as string | string[],
      exp: this.payload.exp as number,
      iat: this.payload.iat as number,
      email: this.payload.email as string | undefined,
      nonce: this.payload.nonce as string | undefined,
      preferred_username: this.payload.preferred_username as string | undefined,
      given_name: this.payload.given_name as string | undefined,
      family_name: this.payload.family_name as string | undefined,
      groups: this.payload.groups as string[] | undefined,
      scopes: this.payload.scopes as string[] | undefined,
    };
  }

  /**
   * Gets the signature bytes
   */
  getSignature(): Uint8Array {
    return this.signature;
  }

  /**
   * Gets the algorithm from the protected header
   */
  getAlgorithm(): string | undefined {
    return this.protected.alg as string | undefined;
  }

  /**
   * Gets the key ID from the protected header
   */
  getKeyId(): string | undefined {
    return this.protected.kid as string | undefined;
  }

  /**
   * Gets the full token bytes
   */
  getToken(): Uint8Array {
    return this.token;
  }

  /**
   * Verifies the JWT signature using the provided public key
   */
  async verify(publicKey: jose.JWK): Promise<boolean> {
    try {
      const key = await jose.importJWK(publicKey);
      const tokenStr = new TextDecoder().decode(this.token);
      await jose.jwtVerify(tokenStr, key);
      return true;
    } catch {
      return false;
    }
  }
}
