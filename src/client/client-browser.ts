/**
 * Browser-compatible OpenPubKey Client
 */

import type { BrowserOpenIdProvider } from '../providers/types.js';
import { PKToken } from '../pktoken/pktoken.js';
import { Claims } from '../pktoken/clientinstance/claims.js';
import { KeyAlgorithm, randomHex, webCryptoAlgorithm } from '../util/crypto.js';
import { Verifier } from '../verifier/verifier.js';
import type { AuthOptions } from './client.js';
import {
  deleteBrowserSigner,
  loadBrowserSigner,
  saveBrowserSigner,
} from './browser-signer-store.js';

const SIGNER_ID_STORAGE_KEY = 'opk_signer_id';
const LEGACY_SIGNER_JWK_STORAGE_KEY = 'opk_signer_jwk';
const ALGORITHM_STORAGE_KEY = 'opk_algorithm';
const CIC_STORAGE_KEY = 'opk_cic_protected';

/**
 * Options for creating an OpenPubKey client (Browser)
 */
export interface ClientBrowserOptions {
  signer?: CryptoKey;
  publicKey?: CryptoKey;
  algorithm?: KeyAlgorithm;
}

/**
 * OpenPubKey Client for Browser
 *
 * Main client for performing OpenPubKey authentication in browser environments
 */
export class OpkClientBrowser {
  private op: BrowserOpenIdProvider;
  private signer: CryptoKey;
  private publicKey?: CryptoKey;
  private algorithm: KeyAlgorithm;
  private pkToken?: PKToken;
  private accessToken?: Uint8Array;

  private constructor(
    op: BrowserOpenIdProvider,
    signer: CryptoKey,
    algorithm: KeyAlgorithm,
    publicKey?: CryptoKey
  ) {
    this.op = op;
    this.signer = signer;
    this.algorithm = algorithm;
    this.publicKey = publicKey;
  }

  /**
   * Creates a new OpenPubKey client for browser
   */
  static async newClient(
    op: BrowserOpenIdProvider,
    options?: ClientBrowserOptions
  ): Promise<OpkClientBrowser> {
    let signer: CryptoKey;
    let publicKey: CryptoKey | undefined;
    let algorithm: KeyAlgorithm;
    if (options?.signer) {
      if (!options.algorithm) {
        throw new Error('Algorithm must be specified when providing a signer');
      }
      algorithm = options.algorithm;
      ({ signer, publicKey } = await normalizeProvidedSigner(
        options.signer,
        algorithm,
        options.publicKey
      ));
    } else {
      algorithm = options?.algorithm || KeyAlgorithm.ES256;
      const keyPair = await generateBrowserKeyPair(algorithm);
      signer = keyPair.privateKey;
      publicKey = keyPair.publicKey;
    }
    return new OpkClientBrowser(op, signer, algorithm, publicKey);
  }

  /**
   * Restores the non-extractable signer saved before the OAuth redirect.
   */
  static async resumeAuth(op: BrowserOpenIdProvider): Promise<OpkClientBrowser> {
    const signerID = sessionStorage.getItem(SIGNER_ID_STORAGE_KEY);
    const storedAlgorithm = sessionStorage.getItem(ALGORITHM_STORAGE_KEY);
    if (!signerID || !storedAlgorithm) {
      throw new Error('No browser authentication signer found');
    }
    if (!isBrowserAlgorithm(storedAlgorithm)) {
      throw new Error(`Unsupported stored browser algorithm: ${storedAlgorithm}`);
    }

    const signer = await loadBrowserSigner(signerID);
    if (!signer) {
      throw new Error('Browser authentication signer is no longer available');
    }
    return new OpkClientBrowser(op, signer, storedAlgorithm);
  }

  /**
   * Initiates authentication with the OpenID Provider.
   * This will redirect the browser to the OAuth provider.
   * After the redirect, call completeAuth() to finish the process.
   */
  async auth(options?: AuthOptions): Promise<never> {
    if (!this.publicKey) {
      throw new Error('A public key is required to initiate browser authentication');
    }

    await OpkClientBrowser.clearStoredAuth();
    const cic = await Claims.newClaims(this.publicKey, options?.extraClaims || {});
    const cicProtected = JSON.stringify(cic.getProtected());
    const signerID = randomHex(16);
    await saveBrowserSigner(signerID, this.signer);
    try {
      sessionStorage.setItem(SIGNER_ID_STORAGE_KEY, signerID);
      sessionStorage.setItem(ALGORITHM_STORAGE_KEY, this.algorithm);
      sessionStorage.setItem(CIC_STORAGE_KEY, cicProtected);
    } catch (error) {
      try {
        await deleteBrowserSigner(signerID);
      } catch (cleanupError) {
        console.error('Failed to remove browser signer after storage error', cleanupError);
      }
      sessionStorage.removeItem(SIGNER_ID_STORAGE_KEY);
      sessionStorage.removeItem(ALGORITHM_STORAGE_KEY);
      sessionStorage.removeItem(CIC_STORAGE_KEY);
      throw error;
    }
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
  getOp(): BrowserOpenIdProvider {
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
    let result: PKToken | undefined;
    let authError: unknown;
    let authFailed = false;
    try {
      const tokens = await this.op.handleCallback();
      if (!tokens || !tokens.idToken) {
        throw new Error('No tokens found in callback');
      }
      this.accessToken = tokens.accessToken;
      const storedCicProtectedStr = sessionStorage.getItem(CIC_STORAGE_KEY);
      if (!storedCicProtectedStr) {
        throw new Error('No CIC found in session storage. Did you call auth() first?');
      }
      let cicProtected: Record<string, unknown>;
      try {
        cicProtected = JSON.parse(storedCicProtectedStr);
      } catch (e) {
        throw new Error(
          `Failed to parse stored CIC: ${e instanceof Error ? e.message : String(e)}`
        );
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
      result = pkt;
    } catch (error) {
      authError = error;
      authFailed = true;
    }

    try {
      await OpkClientBrowser.clearStoredAuth();
    } catch (cleanupError) {
      if (!authFailed) {
        throw cleanupError;
      }
      console.error('Failed to clear browser authentication state', cleanupError);
    }

    if (authFailed) {
      throw authError;
    }
    if (!result) {
      throw new Error('Authentication completed without a PK token');
    }
    return result;
  }

  /**
   * Removes browser authentication state and its transient signer.
   */
  static async clearStoredAuth(): Promise<void> {
    const signerID = sessionStorage.getItem(SIGNER_ID_STORAGE_KEY);
    if (signerID) {
      await deleteBrowserSigner(signerID);
    }
    sessionStorage.removeItem(SIGNER_ID_STORAGE_KEY);
    sessionStorage.removeItem(LEGACY_SIGNER_JWK_STORAGE_KEY);
    sessionStorage.removeItem(ALGORITHM_STORAGE_KEY);
    sessionStorage.removeItem(CIC_STORAGE_KEY);
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

function isBrowserAlgorithm(value: string): value is KeyAlgorithm.ES256 | KeyAlgorithm.RS256 {
  return value === KeyAlgorithm.ES256 || value === KeyAlgorithm.RS256;
}

async function normalizeProvidedSigner(
  signer: CryptoKey,
  algorithm: KeyAlgorithm,
  publicKey?: CryptoKey
): Promise<{ signer: CryptoKey; publicKey?: CryptoKey }> {
  assertBrowserKey(signer, 'private', 'sign', algorithm);
  if (publicKey) {
    assertBrowserKey(publicKey, 'public', 'verify', algorithm);
    await assertMatchingKeyPair(signer, publicKey, algorithm);
  }
  if (!signer.extractable) {
    if (!publicKey) {
      throw new Error('A public key must be provided with a non-extractable signer');
    }
    return { signer, publicKey };
  }

  const privateJwk = await crypto.subtle.exportKey('jwk', signer);
  const { key_ops: _privateKeyOps, ...cleanPrivateJwk } = privateJwk;
  const nonExtractableSigner = await crypto.subtle.importKey(
    'jwk',
    cleanPrivateJwk,
    webCryptoAlgorithm(algorithm).importParams,
    false,
    ['sign']
  );
  if (publicKey) {
    return { signer: nonExtractableSigner, publicKey };
  }

  const publicJwk = publicJwkFromPrivate(privateJwk, algorithm);
  const derivedPublicKey = await crypto.subtle.importKey(
    'jwk',
    publicJwk,
    webCryptoAlgorithm(algorithm).importParams,
    true,
    ['verify']
  );
  return { signer: nonExtractableSigner, publicKey: derivedPublicKey };
}

function publicJwkFromPrivate(privateJwk: JsonWebKey, algorithm: KeyAlgorithm): JsonWebKey {
  switch (algorithm) {
    case KeyAlgorithm.ES256: {
      const { d: _privateScalar, key_ops: _keyOps, ...publicJwk } = privateJwk;
      return publicJwk;
    }
    case KeyAlgorithm.RS256: {
      const {
        d: _privateExponent,
        p: _firstPrime,
        q: _secondPrime,
        dp: _firstExponent,
        dq: _secondExponent,
        qi: _coefficient,
        oth: _otherPrimes,
        key_ops: _keyOps,
        ...publicJwk
      } = privateJwk;
      return publicJwk;
    }
    default:
      throw new Error(`Unsupported algorithm for browser: ${algorithm}`);
  }
}

function assertBrowserKey(
  key: CryptoKey,
  type: KeyType,
  usage: KeyUsage,
  algorithm: KeyAlgorithm
): void {
  const expected = webCryptoAlgorithm(algorithm).importParams;
  const actual = key.algorithm;
  const algorithmMatches =
    actual.name === expected.name &&
    (algorithm !== KeyAlgorithm.ES256 ||
      (actual as EcKeyAlgorithm).namedCurve === (expected as EcKeyImportParams).namedCurve) &&
    (algorithm !== KeyAlgorithm.RS256 ||
      (actual as RsaHashedKeyAlgorithm).hash.name === (expected as RsaHashedImportParams).hash);
  const canExportPublicKey = type !== 'public' || key.extractable;
  if (
    key.type !== type ||
    !key.usages.includes(usage) ||
    !algorithmMatches ||
    !canExportPublicKey
  ) {
    throw new Error(`Browser ${type} key is not a valid ${algorithm} ${usage} key`);
  }
}

async function assertMatchingKeyPair(
  signer: CryptoKey,
  publicKey: CryptoKey,
  algorithm: KeyAlgorithm
): Promise<void> {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const signParams = webCryptoAlgorithm(algorithm).signParams;
  const signature = await crypto.subtle.sign(signParams, signer, challenge);
  const matches = await crypto.subtle.verify(signParams, publicKey, signature, challenge);
  if (!matches) {
    throw new Error('Provided browser public key does not match the signer');
  }
}

async function generateBrowserKeyPair(algorithm: KeyAlgorithm): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(webCryptoAlgorithm(algorithm).generateParams, false, [
    'sign',
    'verify',
  ]) as Promise<CryptoKeyPair>;
}
