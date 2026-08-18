/**
 * Browser-compatible Google OpenID Provider
 * Uses redirect-based OAuth flow instead of local HTTP server
 */

import type { BrowserOpenIdProvider } from './types.js';
import type { Tokens } from '../oidc/tokens.js';
import type { Claims } from '../pktoken/clientinstance/claims.js';
import type { PublicKeyRecord } from '../discover/discover.js';
import { PublicKeyFinder, getJwksByIssuer } from '../discover/discover.js';
import { DefaultProviderVerifier } from './provider-verifier.js';
import { CommitTypes } from './types.js';
import * as jose from 'jose';

// Browser globals - these are available in browser environments
declare const window: Window & { location: Location };
declare const sessionStorage: Storage;

const GOOGLE_ISSUER = 'https://accounts.google.com';
const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';

/**
 * Options for configuring the Google OpenID Provider (Browser)
 */
export interface GoogleBrowserOptions {
  clientID: string;
  issuer: string;
  scopes: string[];
  redirectURI: string;
}

/**
 * Returns default options for Google OAuth (Browser)
 */
export function getDefaultGoogleBrowserOpOptions(): GoogleBrowserOptions {
  return {
    issuer: GOOGLE_ISSUER,
    clientID: '206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com',
    scopes: ['openid', 'profile', 'email'],
    redirectURI: window?.location
      ? `${window.location.protocol}//${window.location.host}/login-callback.html`
      : 'http://localhost:3000/login-callback.html',
  };
}

/**
 * Google OpenID Provider implementation for browsers
 * Uses redirect-based OAuth flow
 */
export class GoogleBrowserOp implements BrowserOpenIdProvider {
  private options: GoogleBrowserOptions;
  private publicKeyFinder: PublicKeyFinder;
  private verifier: DefaultProviderVerifier;

  constructor(options?: Partial<GoogleBrowserOptions>) {
    this.options = { ...getDefaultGoogleBrowserOpOptions(), ...options };
    this.publicKeyFinder = new PublicKeyFinder(async (issuer) => getJwksByIssuer(issuer));
    // Setup provider verifier
    this.verifier = new DefaultProviderVerifier(this.options.issuer, {
      commitType: CommitTypes.NONCE_CLAIM,
      clientID: this.options.clientID,
      skipClientIDCheck: false,
      gqOnly: false,
    });
  }

  issuer(): string {
    return this.options.issuer;
  }

  async publicKeyByKeyId(keyID: string): Promise<PublicKeyRecord> {
    return this.publicKeyFinder.byKeyID(this.options.issuer, keyID);
  }

  async publicKeyByToken(token: Uint8Array): Promise<PublicKeyRecord> {
    return this.publicKeyFinder.byToken(this.options.issuer, token);
  }

  /**
   * Initiates redirect-based OAuth flow
   * This redirects the browser to Google's OAuth page
   */
  async requestTokens(cic: Claims): Promise<Tokens> {
    // Get CIC hash for nonce
    const nonceBytes = await cic.hash();
    const nonce = new TextDecoder().decode(nonceBytes);
    // Generate state for CSRF protection
    const state = this.generateState();
    sessionStorage.setItem('oauth_state', state);
    sessionStorage.setItem('oauth_nonce', nonce);
    // Build authorization URL
    const params = new URLSearchParams({
      client_id: this.options.clientID,
      redirect_uri: this.options.redirectURI,
      response_type: 'id_token',
      scope: this.options.scopes.join(' '),
      state,
      nonce,
    });
    const authUrl = `${GOOGLE_AUTH_URL}?${params.toString()}`;
    // Redirect to Google OAuth
    window.location.href = authUrl;
    // This will never return as we're redirecting
    throw new Error('Redirecting to OAuth provider...');
  }

  /**
   * Handles the OAuth callback after redirect
   * Call this when the page loads after OAuth redirect
   */
  handleCallback(): Tokens | null {
    const hash = window.location.hash.substring(1);
    const params = new URLSearchParams(hash);
    const idToken = params.get('id_token');
    const state = params.get('state');
    const error = params.get('error');
    if (error) {
      throw new Error(`OAuth error: ${error}`);
    }
    if (!idToken) {
      return null;
    }
    // Verify state
    const savedState = sessionStorage.getItem('oauth_state');
    if (state !== savedState) {
      throw new Error('Invalid OAuth state');
    }
    // Clear OAuth state
    sessionStorage.removeItem('oauth_state');
    sessionStorage.removeItem('oauth_nonce');
    // Return tokens
    return {
      idToken: new TextEncoder().encode(idToken),
      accessToken: undefined,
      refreshToken: undefined,
    };
  }

  /**
   * Verify an ID token
   */
  async verifyIDToken(idt: Uint8Array, cic: Claims): Promise<void> {
    return this.verifier.verifyIDToken(idt, cic);
  }

  /**
   * Gets public key by token (for verifier interface)
   */
  async publicKeyByToken_verifier(token: Uint8Array): Promise<jose.JWK> {
    const record = await this.publicKeyByToken(token);
    return record.publicKey;
  }

  /**
   * Generate a random state parameter
   */
  private generateState(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }
}

/**
 * Creates a new Google OpenID Provider for browser with default options
 */
export function newGoogleBrowserOp(): GoogleBrowserOp {
  return new GoogleBrowserOp();
}

/**
 * Creates a new Google OpenID Provider for browser with custom options
 */
export function newGoogleBrowserOpWithOptions(options: Partial<GoogleBrowserOptions>): GoogleBrowserOp {
  return new GoogleBrowserOp(options);
}
