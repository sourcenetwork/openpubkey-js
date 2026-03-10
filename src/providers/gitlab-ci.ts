import type { OpenIdProvider } from './types.js';
import type { Tokens } from '../oidc/tokens.js';
import type { Claims } from '../pktoken/clientinstance/claims.js';
import type { PublicKeyRecord } from '../discover/discover.js';
import { PublicKeyFinder } from '../discover/discover.js';
import { newProviderVerifier } from './provider-verifier.js';
import { CommitTypes } from './types.js';

const GITLAB_ISSUER = 'https://gitlab.com';

/**
 * GitLab CI OpenID Provider implementation
 *
 * This provider is specifically for GitLab CI/CD workflows.
 * It reads tokens from environment variables set by GitLab CI.
 *
 * Note: This implementation does not support GQ signatures (GQ is omitted in TypeScript).
 * It reads the ID token directly from an environment variable.
 */
export class GitlabCiOp implements OpenIdProvider {
  private _issuer: string;
  private tokenEnvVar: string;
  private publicKeyFinder: PublicKeyFinder;

  constructor(issuer: string, tokenEnvVar: string) {
    this._issuer = issuer;
    this.tokenEnvVar = tokenEnvVar;
    this.publicKeyFinder = new PublicKeyFinder();
  }

  /**
   * Creates a GitLab CI OP from environment variables
   * Uses the default environment variable name: OPENPUBKEY_JWT
   */
  static fromEnvironmentDefault(): GitlabCiOp {
    return GitlabCiOp.fromEnvironment('OPENPUBKEY_JWT');
  }

  /**
   * Creates a GitLab CI OP from environment variables
   * @param tokenEnvVar - The name of the environment variable containing the ID token
   */
  static fromEnvironment(tokenEnvVar: string): GitlabCiOp {
    return new GitlabCiOp(GITLAB_ISSUER, tokenEnvVar);
  }

  issuer(): string {
    return this._issuer;
  }

  async publicKeyByKeyId(keyID: string): Promise<PublicKeyRecord> {
    return this.publicKeyFinder.byKeyID(this._issuer, keyID);
  }

  async publicKeyByToken(token: Uint8Array): Promise<PublicKeyRecord> {
    return this.publicKeyFinder.byToken(this._issuer, token);
  }

  /**
   * Request tokens from GitLab CI
   *
   * Note: GitLab CI uses GQ-bound tokens in the Go implementation.
   * Since GQ signatures are not implemented in TypeScript, this reads
   * the ID token directly from the environment variable.
   */
  async requestTokens(_cic: Claims): Promise<Tokens> {
    const idTokenStr = process.env[this.tokenEnvVar];
    if (!idTokenStr) {
      throw new Error(`${this.tokenEnvVar} environment variable not set`);
    }
    const idToken = new TextEncoder().encode(idTokenStr);
    return {
      idToken,
    };
  }

  /**
   * Verify an ID token
   *
   * GitLab CI uses GQ_BOUND commitment type in the Go implementation.
   * Since GQ signatures are not implemented in TypeScript, this will
   * throw an error as GQ verification is not supported.
   */
  async verifyIDToken(idt: Uint8Array, cic: Claims): Promise<void> {
    const vp = newProviderVerifier(this._issuer, {
      commitType: CommitTypes.GQ_BOUND,
      gqOnly: false, // Set to false since GQ is not implemented
      skipClientIDCheck: true,
      discoverPublicKey: this.publicKeyFinder,
    });
    await vp.verifyIDToken(idt, cic);
  }
}

/**
 * Creates a new GitLab CI OpenID Provider from environment variables
 * Uses the default environment variable name: OPENPUBKEY_JWT
 */
export function newGitlabCiOpFromEnvironmentDefault(): GitlabCiOp {
  return GitlabCiOp.fromEnvironmentDefault();
}

/**
 * Creates a new GitLab CI OpenID Provider from environment variables
 * @param tokenEnvVar - The name of the environment variable containing the ID token
 */
export function newGitlabCiOpFromEnvironment(tokenEnvVar: string): GitlabCiOp {
  return GitlabCiOp.fromEnvironment(tokenEnvVar);
}

/**
 * Creates a new GitLab CI OpenID Provider with explicit configuration
 * @param issuer - The GitLab issuer URL
 * @param tokenEnvVar - The name of the environment variable containing the ID token
 */
export function newGitlabCiOp(issuer: string, tokenEnvVar: string): GitlabCiOp {
  return new GitlabCiOp(issuer, tokenEnvVar);
}
