import type { RefreshableOpenIdProvider } from './types.js';
import type { Tokens } from '../oidc/tokens.js';
import type { Claims } from '../pktoken/clientinstance/claims.js';
import type { PublicKeyRecord } from '../discover/discover.js';
import { PublicKeyFinder, getJwksByIssuer } from '../discover/discover.js';
import { OAuthFlow, type OAuthOptions } from '../client/oauth.js';
import { DefaultProviderVerifier } from './provider-verifier.js';
import { CommitTypes } from './types.js';

const GOOGLE_ISSUER = 'https://accounts.google.com';

/**
 * Options for configuring the Google OpenID Provider
 */
export interface GoogleOptions {
  clientID: string;
  clientSecret: string;
  issuer: string;
  scopes: string[];
  promptType: string;
  accessType: string;
  redirectURIs: string[];
  gqSign: boolean;
  issuedAtOffset: number; // milliseconds
  openBrowser?: boolean;
}

/**
 * Returns default options for Google OAuth
 */
export function getDefaultGoogleOpOptions(): GoogleOptions {
  return {
    issuer: GOOGLE_ISSUER,
    clientID: '206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com',
    // The clientSecret was intentionally checked in. It holds no power.
    // Google requires a ClientSecret even for public OIDC apps
    clientSecret: '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',
    scopes: ['openid', 'profile', 'email'],
    promptType: 'consent',
    accessType: 'offline',
    redirectURIs: [
      'http://localhost:3000/login-callback',
      'http://localhost:10001/login-callback',
      'http://localhost:11110/login-callback',
    ],
    gqSign: false,
    issuedAtOffset: 60000, // 1 minute
    openBrowser: true,
  };
}

/**
 * Google OpenID Provider implementation with OAuth flow
 */
export class GoogleOp implements RefreshableOpenIdProvider {
  private options: GoogleOptions;
  private publicKeyFinder: PublicKeyFinder;
  private oauthFlow: OAuthFlow;
  private verifier: DefaultProviderVerifier;

  constructor(options?: Partial<GoogleOptions>) {
    this.options = { ...getDefaultGoogleOpOptions(), ...options };
    this.publicKeyFinder = new PublicKeyFinder(async (issuer) => getJwksByIssuer(issuer));
    // Setup OAuth flow
    const oauthOptions: OAuthOptions = {
      issuer: this.options.issuer,
      clientID: this.options.clientID,
      clientSecret: this.options.clientSecret,
      redirectURIs: this.options.redirectURIs,
      scopes: this.options.scopes,
      promptType: this.options.promptType,
      accessType: this.options.accessType,
      openBrowser: this.options.openBrowser,
    };
    this.oauthFlow = new OAuthFlow(oauthOptions);
    // Setup provider verifier
    this.verifier = new DefaultProviderVerifier(this.options.issuer, {
      commitType: CommitTypes.NONCE_CLAIM,
      clientID: this.options.clientID,
      skipClientIDCheck: false,
      gqOnly: this.options.gqSign,
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
   * Request tokens from Google using OAuth 2.0 Authorization Code Flow with PKCE
   */
  async requestTokens(cic: Claims): Promise<Tokens> {
    return this.oauthFlow.requestTokens(cic);
  }

  /**
   * Refresh tokens using a refresh token
   */
  async refreshTokens(refreshToken: Uint8Array): Promise<Tokens> {
    return this.oauthFlow.refreshTokens(refreshToken);
  }

  /**
   * Verify an ID token
   */
  async verifyIDToken(idt: Uint8Array, cic: Claims): Promise<void> {
    return this.verifier.verifyIDToken(idt, cic);
  }

  /**
   * Verify a refreshed ID token
   */
  async verifyRefreshedIDToken(origIdt: Uint8Array, reIdt: Uint8Array): Promise<void> {
    return this.verifier.verifyRefreshedIDToken(origIdt, reIdt);
  }

}

/**
 * Creates a new Google OpenID Provider with default options
 */
export function newGoogleOp(): GoogleOp {
  return new GoogleOp();
}

/**
 * Creates a new Google OpenID Provider with custom options
 */
export function newGoogleOpWithOptions(options: Partial<GoogleOptions>): GoogleOp {
  return new GoogleOp(options);
}
