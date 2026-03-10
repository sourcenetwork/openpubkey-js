import * as jose from 'jose';
import type { CommitType } from './types.js';
import type { Claims } from '../pktoken/clientinstance/claims.js';
import { PublicKeyFinder, defaultPubkeyFinder } from '../discover/discover.js';

/**
 * Options for provider verifier
 */
export interface ProviderVerifierOpts {
  clientID?: string;
  commitType: CommitType;
  skipClientIDCheck?: boolean;
  discoverPublicKey?: PublicKeyFinder;
  gqOnly?: boolean; // Only allow GQ signatures (intentionally not implemented as GQ is omitted)
}

/**
 * Default provider verifier implementation
 */
export class DefaultProviderVerifier {
  private _issuer: string;
  private commitType: CommitType;
  private options: ProviderVerifierOpts;
  private publicKeyFinder: PublicKeyFinder;

  constructor(issuer: string, options: ProviderVerifierOpts) {
    this._issuer = issuer;
    this.commitType = options.commitType;
    this.options = options;
    this.publicKeyFinder = options.discoverPublicKey || defaultPubkeyFinder();
  }

  issuer(): string {
    return this._issuer;
  }

  /**
   * Verifies an ID token
   * @param idToken - The ID token bytes
   * @param cic - The client instance claims
   */
  async verifyIDToken(idToken: Uint8Array, cic: Claims): Promise<void> {
    // GQ Signature verification is not implemented (intentionally omitted)
    if (this.options.gqOnly) {
      throw new Error(
        'GQ signatures are not supported in this TypeScript implementation (omitted by design)'
      );
    }
    const tokenStr = new TextDecoder().decode(idToken);
    // Parse the ID token
    const payload = jose.decodeJwt(tokenStr);
    const protectedHeader = jose.decodeProtectedHeader(tokenStr);
    // Verify audience if required
    if (!this.options.skipClientIDCheck && this.options.clientID) {
      await this.verifyAudience(payload as jose.JWTPayload, this.options.clientID);
    }
    // Get algorithm
    const alg = protectedHeader.alg;
    if (!alg) {
      throw new Error('Provider algorithm type missing');
    }
    // Get public key from JWKS
    const publicKeyRecord = await this.publicKeyFinder.byToken(this._issuer, idToken);
    // Verify signature using jose
    try {
      const key = await jose.importJWK(publicKeyRecord.publicKey);
      await jose.jwtVerify(tokenStr, key, {
        issuer: this._issuer,
      });
    } catch (error) {
      throw new Error(`Failed to verify ID token signature: ${error}`);
    }
    // Verify commitment (nonce or aud contains hash of CIC)
    if (!this.commitType.gqCommitment) {
      // Standard commitment verification (nonce or aud)
      await this.verifyCommitment(payload as jose.JWTPayload, cic);
    }
  }

  /**
   * Gets the public key by extracting kid from token
   */
  async publicKeyByToken(token: Uint8Array): Promise<jose.JWK> {
    const record = await this.publicKeyFinder.byToken(this._issuer, token);
    return record.publicKey;
  }

  /**
   * Verifies the audience claim
   */
  private async verifyAudience(payload: jose.JWTPayload, expectedClientID: string): Promise<void> {
    const aud = payload.aud;
    if (!aud) {
      throw new Error('Missing audience claim in ID token');
    }
    // Handle array or string audience
    const audiences = Array.isArray(aud) ? aud : [aud];
    if (!audiences.includes(expectedClientID)) {
      throw new Error(
        `Audience mismatch: expected ${expectedClientID}, got ${audiences.join(', ')}`
      );
    }
  }

  /**
   * Verifies the commitment (that nonce or aud contains CIC hash)
   */
  private async verifyCommitment(payload: jose.JWTPayload, cic: Claims): Promise<void> {
    // Calculate expected commitment (hash of CIC)
    const cicHash = await cic.hash();
    const cicHashStr = new TextDecoder().decode(cicHash);
    const claimName = this.commitType.claim;
    if (claimName === 'nonce') {
      // Verify nonce commitment
      const nonce = payload.nonce as string | undefined;
      if (!nonce) {
        throw new Error('Missing nonce claim in ID token');
      }
      if (nonce !== cicHashStr) {
        throw new Error(`Nonce mismatch: expected ${cicHashStr}, got ${nonce}`);
      }
    } else if (claimName === 'aud') {
      // Verify aud commitment
      const aud = payload.aud;
      if (!aud) {
        throw new Error('Missing audience claim for commitment verification');
      }
      const audiences = Array.isArray(aud) ? aud : [aud];
      if (!audiences.includes(cicHashStr)) {
        throw new Error(`Audience does not contain CIC hash: ${cicHashStr}`);
      }
    } else if (claimName) {
      // Custom claim commitment
      const claimValue = payload[claimName] as string | undefined;
      if (!claimValue) {
        throw new Error(`Missing claim '${claimName}' in ID token`);
      }
      if (claimValue !== cicHashStr) {
        throw new Error(
          `Claim '${claimName}' mismatch: expected ${cicHashStr}, got ${claimValue}`
        );
      }
    }
  }

  /**
   * Verifies a refreshed ID token
   */
  async verifyRefreshedIDToken(origIdt: Uint8Array, reIdt: Uint8Array): Promise<void> {
    const origPayload = jose.decodeJwt(new TextDecoder().decode(origIdt));
    const rePayload = jose.decodeJwt(new TextDecoder().decode(reIdt));
    // Verify that critical claims match
    if (origPayload.sub !== rePayload.sub) {
      throw new Error('Subject mismatch between original and refreshed ID tokens');
    }
    if (origPayload.iss !== rePayload.iss) {
      throw new Error('Issuer mismatch between original and refreshed ID tokens');
    }
    // Verify the refreshed token signature
    const tokenStr = new TextDecoder().decode(reIdt);
    const publicKeyRecord = await this.publicKeyFinder.byToken(this._issuer, reIdt);
    try {
      const key = await jose.importJWK(publicKeyRecord.publicKey);
      await jose.jwtVerify(tokenStr, key, {
        issuer: this._issuer,
      });
    } catch (error) {
      throw new Error(`Failed to verify refreshed ID token signature: ${error}`);
    }
  }
}

/**
 * Creates a new provider verifier
 */
export function newProviderVerifier(
  issuer: string,
  options: ProviderVerifierOpts
): DefaultProviderVerifier {
  return new DefaultProviderVerifier(issuer, options);
}
