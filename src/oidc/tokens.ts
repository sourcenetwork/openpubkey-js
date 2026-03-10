/**
 * Tokens represents the set of tokens returned from an OIDC provider
 */
export interface Tokens {
  idToken: Uint8Array; // ID Token (JWT)
  accessToken?: Uint8Array; // Access Token
  refreshToken?: Uint8Array; // Refresh Token
}
