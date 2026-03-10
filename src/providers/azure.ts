import type { RefreshableOpenIdProvider } from './types.js';
import type { Tokens } from '../oidc/tokens.js';
import type { Claims } from '../pktoken/clientinstance/claims.js';
import type { PublicKeyRecord } from '../discover/discover.js';
import { PublicKeyFinder, getJwksByIssuer } from '../discover/discover.js';
import { OAuthFlow, type OAuthOptions } from '../client/oauth.js';
import { DefaultProviderVerifier } from './provider-verifier.js';
import { CommitTypes } from './types.js';
import * as jose from 'jose';

/**
 * Options for configuring the Azure OpenID Provider
 */
export interface AzureOptions {
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
  tenantID: string;
}

/**
 * Returns the Azure issuer URL for a given tenant ID
 * @param tenantID - The Azure tenant ID (GUID)
 * @returns The issuer URL
 */
export function azureIssuer(tenantID: string): string {
  return `https://login.microsoftonline.com/${tenantID}/v2.0`;
}

/**
 * Returns default options for Azure OAuth
 * Uses the default consumer tenant ID for non-organizational accounts
 */
export function getDefaultAzureOpOptions(): AzureOptions {
  const defaultTenantID = '9188040d-6c67-4c5b-b112-36a304b66dad'; // Consumer tenant
  return {
    issuer: azureIssuer(defaultTenantID),
    clientID: '096ce0a3-5e72-4da8-9c86-12924b294a01',
    clientSecret: '',
    scopes: ['openid', 'profile', 'email', 'offline_access'], // offline_access required for refresh tokens
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
    tenantID: defaultTenantID,
  };
}

/**
 * Azure OpenID Provider implementation with OAuth flow
 *
 * Azure has a different issuer URI for each tenant. Users that are not part of
 * an Azure organization (Microsoft calls them "consumers") have a default
 * tenant ID of "9188040d-6c67-4c5b-b112-36a304b66dad".
 *
 * More details: https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens
 */
export class AzureOp implements RefreshableOpenIdProvider {
  private options: AzureOptions;
  private publicKeyFinder: PublicKeyFinder;
  private oauthFlow: OAuthFlow;
  private verifier: DefaultProviderVerifier;

  constructor(options?: Partial<AzureOptions>) {
    this.options = { ...getDefaultAzureOpOptions(), ...options };
    // Update issuer if tenantID was provided
    if (options?.tenantID && !options?.issuer) {
      this.options.issuer = azureIssuer(options.tenantID);
    }
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
 * Creates a new Azure OpenID Provider with default options
 */
export function newAzureOp(options?: Partial<AzureOptions>): AzureOp {
  return new AzureOp(options);
}
