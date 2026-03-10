import type { RefreshableOpenIdProvider } from './types.js';
import type { Tokens } from '../oidc/tokens.js';
import type { Claims } from '../pktoken/clientinstance/claims.js';
import type { PublicKeyRecord } from '../discover/discover.js';
import { PublicKeyFinder, getJwksByIssuer } from '../discover/discover.js';
import { OAuthFlow, type OAuthOptions } from '../client/oauth.js';
import { DefaultProviderVerifier } from './provider-verifier.js';
import { CommitTypes } from './types.js';
import * as jose from 'jose';

const GITLAB_ISSUER = 'https://gitlab.com';

/**
 * Options for configuring the GitLab OpenID Provider
 */
export interface GitlabOptions {
  clientID: string;
  clientSecret?: string;
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
 * Returns default options for GitLab OAuth
 */
export function getDefaultGitlabOpOptions(): GitlabOptions {
  return {
    issuer: GITLAB_ISSUER,
    clientID: '8d8b7024572c7fd501f64374dec6bba37096783dfcd792b3988104be08cb6923',
    clientSecret: '',
    scopes: ['openid', 'email'],
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
 * GitLab OpenID Provider implementation with OAuth flow
 */
export class GitlabOp implements RefreshableOpenIdProvider {
  private options: GitlabOptions;
  private publicKeyFinder: PublicKeyFinder;
  private oauthFlow: OAuthFlow;
  private verifier: DefaultProviderVerifier;

  constructor(options?: Partial<GitlabOptions>) {
    this.options = { ...getDefaultGitlabOpOptions(), ...options };
    this.publicKeyFinder = new PublicKeyFinder(async (issuer) => getJwksByIssuer(issuer));
    this.oauthFlow = new OAuthFlow(this.createOAuthOptions());
    this.verifier = new DefaultProviderVerifier(this.options.issuer, {
      clientID: this.options.clientID,
      commitType: CommitTypes.NONCE_CLAIM,
      skipClientIDCheck: false,
      discoverPublicKey: this.publicKeyFinder,
      gqOnly: this.options.gqSign,
    });
  }

  private createOAuthOptions(): OAuthOptions {
    return {
      issuer: this.options.issuer,
      clientID: this.options.clientID,
      clientSecret: this.options.clientSecret,
      scopes: this.options.scopes,
      redirectURIs: this.options.redirectURIs,
      promptType: this.options.promptType,
      accessType: this.options.accessType,
      openBrowser: this.options.openBrowser,
    };
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

  async requestTokens(cic: Claims): Promise<Tokens> {
    return this.oauthFlow.requestTokens(cic);
  }

  async refreshTokens(refreshToken: Uint8Array): Promise<Tokens> {
    return this.oauthFlow.refreshTokens(refreshToken);
  }

  async verifyIDToken(idt: Uint8Array, cic: Claims): Promise<void> {
    await this.verifier.verifyIDToken(idt, cic);
  }

  async verifyRefreshedIDToken(origIdt: Uint8Array, reIdt: Uint8Array): Promise<void> {
    const origToken = new TextDecoder().decode(origIdt);
    const reToken = new TextDecoder().decode(reIdt);
    const origPayload = jose.decodeJwt(origToken);
    const rePayload = jose.decodeJwt(reToken);
    if (origPayload.sub !== rePayload.sub) {
      throw new Error('Subject mismatch between original and refreshed ID tokens');
    }
    if (origPayload.iss !== rePayload.iss) {
      throw new Error('Issuer mismatch between original and refreshed ID tokens');
    }
  }
}

/**
 * Creates a new GitLab OpenID Provider with default options
 */
export function newGitlabOp(options?: Partial<GitlabOptions>): GitlabOp {
  return new GitlabOp(options);
}
