import type { OpenIdProvider } from './types.js';
import type { Tokens } from '../oidc/tokens.js';
import type { Claims } from '../pktoken/clientinstance/claims.js';
import type { PublicKeyRecord } from '../discover/discover.js';
import { PublicKeyFinder } from '../discover/discover.js';
import { newProviderVerifier } from './provider-verifier.js';
import { CommitTypes } from './types.js';

const GITHUB_ISSUER = 'https://token.actions.githubusercontent.com';

/**
 * GitHub Actions OpenID Provider implementation
 *
 * This provider is specifically for GitHub Actions workflows.
 * It reads tokens from environment variables set by GitHub Actions.
 */
export class GithubOp implements OpenIdProvider {
  private tokenURL: string;
  private tokenRequestAuthToken: string;
  private publicKeyFinder: PublicKeyFinder;

  constructor(tokenURL: string, token: string) {
    this.tokenURL = tokenURL;
    this.tokenRequestAuthToken = token;
    this.publicKeyFinder = new PublicKeyFinder();
  }

  /**
   * Creates a GitHub OP from environment variables
   * Reads ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN
   */
  static fromEnvironment(): GithubOp {
    const tokenURL = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
    const token = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    if (!tokenURL) {
      throw new Error('ACTIONS_ID_TOKEN_REQUEST_URL environment variable not set');
    }
    if (!token) {
      throw new Error('ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable not set');
    }
    return new GithubOp(tokenURL, token);
  }

  issuer(): string {
    return GITHUB_ISSUER;
  }

  async publicKeyByKeyId(keyID: string): Promise<PublicKeyRecord> {
    return this.publicKeyFinder.byKeyID(GITHUB_ISSUER, keyID);
  }

  async publicKeyByToken(token: Uint8Array): Promise<PublicKeyRecord> {
    return this.publicKeyFinder.byToken(GITHUB_ISSUER, token);
  }

  /**
   * Request tokens from GitHub Actions
   */
  async requestTokens(cic: Claims): Promise<Tokens> {
    // Build token URL with audience parameter (CIC hash)
    const commitment = await cic.hash();
    const commitmentStr = new TextDecoder().decode(commitment);
    const url = new URL(this.tokenURL);
    url.searchParams.set('audience', commitmentStr);
    const response = await fetch(url.toString(), {
      headers: {
        Authorization: `Bearer ${this.tokenRequestAuthToken}`,
      },
    });
    if (!response.ok) {
      throw new Error(`Failed to get token from GitHub: ${response.statusText}`);
    }
    const data = (await response.json()) as { value: string };
    const idToken = new TextEncoder().encode(data.value);
    return {
      idToken,
    };
  }

  /**
   * Verify an ID token
   *
   * GitHub Actions uses AUD_CLAIM commitment type where the audience contains
   * the hash of the CIC (Client Instance Claims). We verify using the provider
   * verifier and skip the client ID check since GitHub Actions doesn't have a
   * traditional OAuth client ID.
   */
  async verifyIDToken(idt: Uint8Array, cic: Claims): Promise<void> {
    const vp = newProviderVerifier(GITHUB_ISSUER, {
      commitType: CommitTypes.AUD_CLAIM,
      gqOnly: false, // Set to false since GQ is not implemented in TypeScript
      skipClientIDCheck: true,
      discoverPublicKey: this.publicKeyFinder,
    });

    await vp.verifyIDToken(idt, cic);
  }
}

/**
 * Creates a new GitHub OpenID Provider from environment variables
 */
export function newGithubOpFromEnvironment(): GithubOp {
  return GithubOp.fromEnvironment();
}

/**
 * Creates a new GitHub OpenID Provider with explicit credentials
 */
export function newGithubOp(tokenURL: string, token: string): GithubOp {
  return new GithubOp(tokenURL, token);
}
