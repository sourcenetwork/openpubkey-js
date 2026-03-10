import * as crypto from 'crypto';
import type { PKToken } from '../pktoken/pktoken.js';
import type { CosignerClaims } from '../pktoken/cos.js';
import { KeyAlgorithm } from '../util/crypto.js';

/**
 * Cosigner provides the ability to add cosigner signatures to PK Tokens
 *
 * A cosigner is a trusted third party that adds an additional signature
 * to a PK Token after authenticating the user through a separate channel
 * (e.g., MFA, email verification, etc.)
 */
export class Cosigner {
  protected alg: KeyAlgorithm;
  protected signer: crypto.KeyObject;

  constructor(signer: crypto.KeyObject, alg: KeyAlgorithm) {
    this.signer = signer;
    this.alg = alg;
  }

  getAlgorithm(): KeyAlgorithm {
    return this.alg;
  }

  /**
   * Cosigns a PK Token with the provided cosigner claims
   *
   * @param pkt - The PK Token to cosign
   * @param cosClaims - The cosigner claims to include in the protected headers
   * @returns The cosigner signature bytes
   */
  async cosign(pkt: PKToken, cosClaims: CosignerClaims): Promise<Uint8Array> {
    // Convert claims to headers object
    const headers: Record<string, unknown> = {
      iss: cosClaims.iss,
      kid: cosClaims.kid,
      alg: cosClaims.alg,
      eid: cosClaims.eid,
      auth_time: cosClaims.auth_time,
      iat: cosClaims.iat,
      exp: cosClaims.exp,
      ruri: cosClaims.ruri,
      nonce: cosClaims.nonce,
      typ: cosClaims.typ || 'cos',
    };
    return pkt.signToken(this.signer, this.alg.toString(), headers);
  }
}
