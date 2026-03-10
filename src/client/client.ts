import * as crypto from 'crypto';
import { exportJWK, type JWK } from 'jose';
import { type OpenIdProvider, isRefreshable, isCosignerCapable } from '../providers/types.js';
import { PKToken } from '../pktoken/pktoken.js';
import { Claims } from '../pktoken/clientinstance/claims.js';
import { genKeyPair, KeyAlgorithm } from '../util/crypto.js';
import { Verifier } from '../verifier/verifier.js';
import { CosignerProvider } from './cosigner.js';

/**
 * Options for creating an OpenPubKey client
 */
export interface ClientOptions {
  signer?: crypto.KeyObject;
  algorithm?: KeyAlgorithm;
  cosignerProvider?: CosignerProvider;
}

/**
 * Options for authentication
 */
export interface AuthOptions {
  extraClaims?: Record<string, unknown>;
}

/**
 * OpenPubKey Client
 *
 * Main client for performing OpenPubKey authentication
 */
export class OpkClient {
  private op: OpenIdProvider;
  private cosP?: CosignerProvider;
  private signer: crypto.KeyObject;
  private algorithm: KeyAlgorithm;
  private pkToken?: PKToken;
  private refreshToken?: Uint8Array;
  private accessToken?: Uint8Array;

  private constructor(
    op: OpenIdProvider,
    signer: crypto.KeyObject,
    algorithm: KeyAlgorithm,
    cosP?: CosignerProvider
  ) {
    this.op = op;
    this.signer = signer;
    this.algorithm = algorithm;
    this.cosP = cosP;
  }

  /**
   * Creates a new OpenPubKey client
   * @param op - The OpenID Provider to use
   * @param options - Client options
   */
  static async newClient(op: OpenIdProvider, options?: ClientOptions): Promise<OpkClient> {
    let signer: crypto.KeyObject;
    let algorithm: KeyAlgorithm;
    if (options?.signer) {
      if (!options.algorithm) {
        throw new Error('Algorithm must be specified when providing a signer');
      }
      signer = options.signer;
      algorithm = options.algorithm;
    } else {
      // Generate default ES256 key pair
      algorithm = options?.algorithm || KeyAlgorithm.ES256;
      signer = (await genKeyPair(algorithm)) as crypto.KeyObject;
    }
    return new OpkClient(op, signer, algorithm, options?.cosignerProvider);
  }

  /**
   * Authenticates with the OpenID Provider and creates a PK Token
   * @param options - Authentication options
   * @returns The PK Token
   */
  async auth(options?: AuthOptions): Promise<PKToken> {
    // If no Cosigner is set, do standard OIDC authentication
    if (!this.cosP) {
      return this.oidcAuth(options);
    }
    // If a Cosigner is set, check that provider supports it
    if (!isCosignerCapable(this.op)) {
      throw new Error('OP supplied does not have support for MFA Cosigner');
    }
    // Perform standard OIDC auth first
    const cosignerOp = this.op;
    const pkt = await this.oidcAuth(options);
    // Then request cosigner signature
    const pktCos = await this.cosP.requestToken(this.signer, pkt, (redirectUri) => {
      // Hook into the HTTP session to redirect to cosigner
      cosignerOp.hookHTTPSession((res) => {
        res.redirect(redirectUri);
      });
    });
    this.pkToken = pktCos;
    return pktCos.deepCopy();
  }

  /**
   * Performs standard OIDC authentication
   * @private
   */
  private async oidcAuth(options?: AuthOptions): Promise<PKToken> {
    // Export public key as JWK
    const publicKey = crypto.createPublicKey(this.signer);
    const jwk = (await exportJWK(publicKey)) as JWK;
    jwk.alg = this.algorithm;
    // Create client instance claims with extra claims
    const cic = await Claims.newClaims(publicKey, options?.extraClaims || {});
    // Request tokens from provider
    const tokens = await this.op.requestTokens(cic);
    this.refreshToken = tokens.refreshToken;
    this.accessToken = tokens.accessToken;
    // Sign the ID token payload with CIC
    const cicToken = await cic.sign(this.signer, this.algorithm, tokens.idToken);
    // Create PK Token
    const pkt = await PKToken.newPKToken(tokens.idToken, cicToken);
    // Verify the PK Token
    const verifier = await Verifier.newVerifier(this.op);
    await verifier.verifyPKToken(pkt);
    return pkt;
  }

  /**
   * Gets the signer (private key)
   */
  getSigner(): crypto.KeyObject {
    return this.signer;
  }

  /**
   * Gets the algorithm
   */
  getAlgorithm(): KeyAlgorithm {
    return this.algorithm;
  }

  /**
   * Gets the OpenID Provider
   */
  getOp(): OpenIdProvider {
    return this.op;
  }

  /**
   * Gets the Cosigner Provider
   */
  getCosP(): CosignerProvider | undefined {
    return this.cosP;
  }

  /**
   * Gets the access token
   */
  getAccessToken(): Uint8Array | undefined {
    return this.accessToken;
  }

  /**
   * Gets a copy of the current PK Token
   */
  async getPKToken(): Promise<PKToken | undefined> {
    return this.pkToken ? this.pkToken.deepCopy() : undefined;
  }

  /**
   * Sets the PK Token
   */
  setPKToken(pkt: PKToken): void {
    this.pkToken = pkt;
  }

  /**
   * Refreshes the ID Token and Access Token using the refresh token
   *
   * This method uses a Refresh Token to request fresh ID Token and Access Token
   * from an OpenID Provider that supports refresh requests. This allows the client
   * to continue making authenticated requests without requiring the user to re-authenticate.
   *
   * @returns A copy of the updated PK Token with the fresh ID Token
   * @throws Error if the provider doesn't support refresh, or if no refresh token or PK Token is set
   */
  async refresh(): Promise<PKToken> {
    // Check if provider supports refresh
    if (!isRefreshable(this.op)) {
      throw new Error(
        `OP (issuer=${this.op.issuer()}) does not support OIDC refresh requests`
      );
    }
    // Validate state
    if (!this.refreshToken) {
      throw new Error('No refresh token set');
    }
    if (!this.pkToken) {
      throw new Error('No PK Token set, run auth() to create a PK Token first');
    }
    // Request new tokens from provider
    const tokens = await this.op.refreshTokens(this.refreshToken);
    // Update the PK Token with the fresh ID Token
    this.pkToken.freshIDToken = tokens.idToken;
    this.refreshToken = tokens.refreshToken;
    this.accessToken = tokens.accessToken;
    // Return a copy of the updated PK Token
    return this.pkToken.deepCopy();
  }
}
