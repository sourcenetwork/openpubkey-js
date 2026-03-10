/**
 * Browser-compatible OpenPubKey Client
 */

import type { OpenIdProvider } from '../providers/types.js';
import type { Tokens } from '../oidc/tokens.js';
import { PKToken } from '../pktoken/pktoken.js';
import { Claims } from '../pktoken/clientinstance/claims.js';
import { genKeyPair, KeyAlgorithm } from '../util/crypto.js';
import { Verifier } from '../verifier/verifier.js';
import type { AuthOptions } from './client.js';

/**
 * Maps KeyAlgorithm to Web Crypto API algorithm parameters
 */
function webCryptoAlgorithm(alg: KeyAlgorithm): AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams {
  switch (alg) {
    case KeyAlgorithm.ES256:
      return { name: 'ECDSA', namedCurve: 'P-256' };
    case KeyAlgorithm.RS256:
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    default:
      throw new Error(`Unsupported algorithm for browser: ${alg}`);
  }
}

// Browser provider with handleCallback method
interface BrowserOpenIdProvider extends OpenIdProvider {
  handleCallback(): Tokens | null;
}

/**
 * Options for creating an OpenPubKey client (Browser)
 */
export interface ClientBrowserOptions {
  signer?: CryptoKey;
  algorithm?: KeyAlgorithm;
}

/**
 * OpenPubKey Client for Browser
 *
 * Main client for performing OpenPubKey authentication in browser environments
 */
export class OpkClientBrowser {
  private op: OpenIdProvider;
  private signer: CryptoKey;
  private algorithm: KeyAlgorithm;
  private pkToken?: PKToken;
  private accessToken?: Uint8Array;

  private constructor(op: OpenIdProvider, signer: CryptoKey, algorithm: KeyAlgorithm) {
    this.op = op;
    this.signer = signer;
    this.algorithm = algorithm;
  }

  /**
   * Creates a new OpenPubKey client for browser
   */
  static async newClient(
    op: OpenIdProvider,
    options?: ClientBrowserOptions
  ): Promise<OpkClientBrowser> {
    let signer: CryptoKey;
    let algorithm: KeyAlgorithm;
    if (options?.signer) {
      if (!options.algorithm) {
        throw new Error('Algorithm must be specified when providing a signer');
      }
      signer = options.signer;
      algorithm = options.algorithm;
    } else {
      algorithm = options?.algorithm || KeyAlgorithm.ES256;
      signer = (await genKeyPair(algorithm)) as CryptoKey;
    }
    return new OpkClientBrowser(op, signer, algorithm);
  }

  /**
   * Initiates authentication with the OpenID Provider.
   * This will redirect the browser to the OAuth provider.
   * After the redirect, call completeAuth() to finish the process.
   */
  async auth(options?: AuthOptions): Promise<never> {
    const privateKeyJwk = await crypto.subtle.exportKey('jwk', this.signer);
    sessionStorage.setItem('opk_signer_jwk', JSON.stringify(privateKeyJwk));
    sessionStorage.setItem('opk_algorithm', this.algorithm);
    // Extract public key only
    const { d: _d, key_ops: _keyOps, ...publicKeyOnly } = privateKeyJwk;
    const jwk: JsonWebKey = { ...publicKeyOnly, alg: this.algorithm };
    const pubKeyForClaims = await crypto.subtle.importKey(
      'jwk',
      jwk,
      webCryptoAlgorithm(this.algorithm),
      true,
      ['verify']
    );
    const cic = await Claims.newClaims(pubKeyForClaims, options?.extraClaims || {});
    const cicProtected = cic.getProtected();
    sessionStorage.setItem('opk_cic_protected', JSON.stringify(cicProtected));
    await this.op.requestTokens(cic);
    throw new Error('Expected redirect to OAuth provider');
  }

  /**
   * Gets the signer (private key)
   */
  getSigner(): CryptoKey {
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
   * Gets the access token
   */
  getAccessToken(): Uint8Array | undefined {
    return this.accessToken;
  }

  /**
   * Completes authentication after OAuth redirect callback.
   * Call this after the browser redirects back from the OAuth provider.
   */
  async completeAuth(): Promise<PKToken> {
    const browserOp = this.op as BrowserOpenIdProvider;
    const tokens = browserOp.handleCallback();
    if (!tokens || !tokens.idToken) {
      throw new Error('No tokens found in callback');
    }
    this.accessToken = tokens.accessToken;
    const storedCicProtectedStr = sessionStorage.getItem('opk_cic_protected');
    if (!storedCicProtectedStr) {
      throw new Error('No CIC found in session storage. Did you call auth() first?');
    }
    let cicProtected: Record<string, unknown>;
    try {
      cicProtected = JSON.parse(storedCicProtectedStr);
    } catch (e) {
      throw new Error(`Failed to parse stored CIC: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (!cicProtected || typeof cicProtected !== 'object') {
      throw new Error(`Invalid CIC format in storage: ${typeof cicProtected}`);
    }
    const cic = Claims.parseClaims(cicProtected);
    const cicToken = await cic.sign(this.signer, this.algorithm, tokens.idToken);
    const pkt = await PKToken.newPKToken(tokens.idToken, cicToken);
    const verifier = await Verifier.newVerifier(this.op);
    await verifier.verifyPKToken(pkt);
    this.pkToken = pkt;
    sessionStorage.removeItem('opk_cic_protected');
    return pkt;
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
}
