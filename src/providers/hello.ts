import type { OpenIdProvider } from './types.js';
import type { Tokens } from '../oidc/tokens.js';
import type { Claims } from '../pktoken/clientinstance/claims.js';
import type { PublicKeyRecord } from '../discover/discover.js';
import { PublicKeyFinder, getJwksByIssuer } from '../discover/discover.js';
import { OAuthFlow, type OAuthOptions } from '../client/oauth.js';
import { DefaultProviderVerifier } from './provider-verifier.js';
import { CommitTypes } from './types.js';

const HELLO_ISSUER = 'https://issuer.hello.coop';

/**
 * Options for configuring the Hello (Hellō) OpenID Provider
 *
 * Hellō is a generic OIDC provider that can be used as a template
 * for implementing custom OIDC providers.
 */
export interface HelloOptions {
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
 * Returns default options for Hello OAuth
 */
export function getDefaultHelloOpOptions(): HelloOptions {
  return {
    issuer: HELLO_ISSUER,
    clientID: 'app_xejobTKEsDNSRd5vofKB2iay_2rN',
    clientSecret: '',
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
 * Hello (Hellō) OpenID Provider implementation with OAuth flow
 *
 * This is a generic OIDC provider implementation that can be used
 * as a template for other custom OIDC providers. Hellō is a universal
 * login provider that provides decentralized identity.
 */
export class HelloOp implements OpenIdProvider {
  private options: HelloOptions;
  private publicKeyFinder: PublicKeyFinder;
  private oauthFlow: OAuthFlow;
  private verifier: DefaultProviderVerifier;

  constructor(options?: Partial<HelloOptions>) {
    this.options = { ...getDefaultHelloOpOptions(), ...options };
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

  async verifyIDToken(idt: Uint8Array, cic: Claims): Promise<void> {
    await this.verifier.verifyIDToken(idt, cic);
  }
}

/**
 * Creates a new Hello OpenID Provider with default options
 */
export function newHelloOp(options?: Partial<HelloOptions>): HelloOp {
  return new HelloOp(options);
}
