import * as crypto from 'crypto';
import * as jose from 'jose';
import { Cosigner } from './cosigner.js';
import type { AuthStateStore } from './authstatestore.js';
import type { PKToken } from '../pktoken/pktoken.js';
import type { AuthState } from './authstate.js';
import type { InitMFAAuth } from './msgs.js';
import { KeyAlgorithm } from '../util/crypto.js';
import { SignatureType } from '../pktoken/pktoken.js';

/**
 * AuthCosigner extends Cosigner with authentication state management
 *
 * This class handles the full MFA cosigner flow including:
 * - Initializing authentication sessions
 * - Issuing authcodes
 * - Redeeming authcodes and issuing cosigner signatures
 */
export class AuthCosigner extends Cosigner {
  private issuer: string;
  private keyID: string;
  private authStateStore: AuthStateStore;

  constructor(
    signer: crypto.KeyObject,
    alg: KeyAlgorithm,
    issuer: string,
    keyID: string,
    store: AuthStateStore
  ) {
    super(signer, alg);
    this.issuer = issuer;
    this.keyID = keyID;
    this.authStateStore = store;
  }

  /**
   * Initializes an authentication session
   *
   * @param pkt - The PK Token
   * @param sig - The signed InitMFAAuth message
   * @returns The authentication session ID
   */
  async initAuth(pkt: PKToken, sig: Uint8Array): Promise<string> {
    // Verify the signed message
    const msgBytes = await pkt.verifySignedMessage(sig);
    const msg = JSON.parse(new TextDecoder().decode(msgBytes)) as InitMFAAuth;
    // Validate the message
    if (msg.iss !== this.issuer) {
      throw new Error(
        `Signed message is for wrong cosigner, got issuer=(${msg.iss}), expected issuer=(${this.issuer})`
      );
    }
    const now = Date.now() / 1000; // Convert to seconds
    const timeDiff = Math.abs(now - msg.time);
    if (timeDiff > 120) {
      throw new Error(
        `Timestamp (${msg.time}) in InitMFAAuth message too far from current time (${now})`
      );
    }
    // Create a new authentication session
    const authID = await this.authStateStore.createNewAuthSession(pkt, msg.ruri, msg.nonce);
    return authID;
  }

  /**
   * Creates a new authcode for an authentication session
   *
   * @param authID - The authentication session ID
   * @returns The authcode
   */
  async newAuthcode(authID: string): Promise<string> {
    return this.authStateStore.createAuthcode(authID);
  }

  /**
   * Redeems an authcode and issues a cosigner signature
   *
   * @param sig - The signed authcode message
   * @returns The cosigner signature
   */
  async redeemAuthcode(sig: Uint8Array): Promise<Uint8Array> {
    // Parse the signed message to get the authcode
    const sigStr = new TextDecoder().decode(sig);
    const parts = sigStr.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWS format');
    }
    const payloadBytes = jose.base64url.decode(parts[1]);
    const authcode = new TextDecoder().decode(payloadBytes);
    // Redeem the authcode
    const { authState, authID } = await this.authStateStore.redeemAuthcode(authcode);
    // Verify the signature after redeeming (prevents reuse)
    const pkt = authState.pkt;
    await pkt.verifySignedMessage(sig);
    // Issue the cosigner signature
    return this.issueSignature(pkt, authState, authID);
  }

  /**
   * Issues a cosigner signature for an authenticated session
   *
   * @param pkt - The PK Token
   * @param authState - The authentication state
   * @param authID - The authentication session ID
   * @returns The cosigner signature
   */
  async issueSignature(pkt: PKToken, authState: AuthState, authID: string): Promise<Uint8Array> {
    const now = Math.floor(Date.now() / 1000); // Unix timestamp in seconds
    const protectedHeaders = {
      iss: this.issuer,
      kid: this.keyID,
      alg: this.alg.toString(),
      eid: authID,
      auth_time: now,
      iat: now,
      exp: now + 3600,
      ruri: authState.redirectURI,
      nonce: authState.nonce,
      typ: SignatureType.COS,
    };
    return this.cosign(pkt, protectedHeaders);
  }
}

/**
 * Creates a new AuthCosigner
 *
 * @param signer - The signing key
 * @param alg - The algorithm
 * @param issuer - The cosigner issuer
 * @param keyID - The key ID
 * @param store - The auth state store
 * @returns A new AuthCosigner instance
 */
export function newAuthCosigner(
  signer: crypto.KeyObject,
  alg: KeyAlgorithm,
  issuer: string,
  keyID: string,
  store: AuthStateStore
): AuthCosigner {
  return new AuthCosigner(signer, alg, issuer, keyID, store);
}
