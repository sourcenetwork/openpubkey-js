import type { Tokens } from '../oidc/tokens.js';
import type { Claims } from '../pktoken/clientinstance/claims.js';
import type { PublicKeyRecord } from '../discover/discover.js';

/**
 * Interface for interacting with an OpenID Provider
 */
export interface OpenIdProvider {
  /**
   * Requests tokens from the OP using the authorization code flow
   * @param cic - The client instance claims
   * @returns The tokens (ID token, access token, refresh token)
   */
  requestTokens(cic: Claims): Promise<Tokens>;

  /**
   * Gets a public key by its key ID
   * @param keyID - The key ID
   * @returns The public key record
   */
  publicKeyByKeyId(keyID: string): Promise<PublicKeyRecord>;

  /**
   * Gets a public key by extracting the key ID from a token
   * @param token - The JWT token
   * @returns The public key record
   */
  publicKeyByToken(token: Uint8Array): Promise<PublicKeyRecord>;

  /**
   * Returns the OpenID provider issuer (e.g., "https://accounts.google.com")
   */
  issuer(): string;

  /**
   * Verifies an ID token
   * @param idt - The ID token bytes
   * @param cic - The client instance claims
   */
  verifyIDToken(idt: Uint8Array, cic: Claims): Promise<void>;
}

/**
 * Interface for an OpenID Provider that supports token refresh
 */
export interface RefreshableOpenIdProvider extends OpenIdProvider {
  /**
   * Refreshes tokens using a refresh token
   * @param refreshToken - The refresh token
   * @returns The new tokens
   */
  refreshTokens(refreshToken: Uint8Array): Promise<Tokens>;

  /**
   * Verifies a refreshed ID token against the original
   * @param origIdt - The original ID token
   * @param reIdt - The refreshed ID token
   */
  verifyRefreshedIDToken(origIdt: Uint8Array, reIdt: Uint8Array): Promise<void>;
}

/**
 * Commit type for binding the commitment to the ID token
 */
export interface CommitType {
  claim: string;
  gqCommitment: boolean;
}

/**
 * Enum of available commit types
 */
export const CommitTypes = {
  NONCE_CLAIM: { claim: 'nonce', gqCommitment: false } as CommitType,
  AUD_CLAIM: { claim: 'aud', gqCommitment: false } as CommitType,
  GQ_BOUND: { claim: '', gqCommitment: true } as CommitType,
};

/**
 * Interface for an OpenID Provider that supports MFA cosigner HTTP session hooking
 */
export interface CosignerCapableProvider extends OpenIdProvider {
  hookHTTPSession(handler: (res: { redirect(url: string): void }) => void): void;
}

/**
 * Type guard to check if a provider supports token refresh
 */
export function isRefreshable(op: OpenIdProvider): op is RefreshableOpenIdProvider {
  return (
    'refreshTokens' in op &&
    typeof (op as RefreshableOpenIdProvider).refreshTokens === 'function'
  );
}

/**
 * Type guard to check if a provider supports MFA cosigner
 */
export function isCosignerCapable(op: OpenIdProvider): op is CosignerCapableProvider {
  return (
    'hookHTTPSession' in op &&
    typeof (op as CosignerCapableProvider).hookHTTPSession === 'function'
  );
}
