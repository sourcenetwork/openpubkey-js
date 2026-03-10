import type { PKToken } from '../pktoken/pktoken.js';

/**
 * User key uniquely identifies a user across authentication sessions
 */
export interface UserKey {
  /** ID Token issuer (iss) */
  issuer: string;
  /** ID Token audience (aud) */
  aud: string;
  /** ID Token subject ID (sub) */
  sub: string;
}

/**
 * AuthState represents the state of an authentication session for cosigning
 *
 * It stores information about the user being authenticated and tracks
 * whether an authcode has been issued and redeemed.
 */
export class AuthState {
  /** The PK Token being authenticated */
  pkt: PKToken;
  /** ID Token issuer (iss) */
  issuer: string;
  /** ID Token audience (aud) */
  aud: string;
  /** ID Token subject ID (sub) */
  sub: string;
  /** ID Token email or username */
  username: string;
  /** ID Token display name (or username if none given) */
  displayName: string;
  /** Redirect URI */
  redirectURI: string;
  /** Nonce supplied by user */
  nonce: string;
  /** Has an authcode been issued for this auth session */
  authcodeIssued: boolean;
  /** Was the PKT cosigned */
  authcodeRedeemed: boolean;

  constructor(
    pkt: PKToken,
    issuer: string,
    aud: string,
    sub: string,
    username: string,
    displayName: string,
    redirectURI: string,
    nonce: string
  ) {
    this.pkt = pkt;
    this.issuer = issuer;
    this.aud = aud;
    this.sub = sub;
    this.username = username;
    this.displayName = displayName;
    this.redirectURI = redirectURI;
    this.nonce = nonce;
    this.authcodeIssued = false;
    this.authcodeRedeemed = false;
  }

  /**
   * Returns the user key for this authentication session
   */
  userKey(): UserKey {
    return {
      issuer: this.issuer,
      aud: this.aud,
      sub: this.sub,
    };
  }
}

/**
 * Creates a new AuthState from a PK Token and request parameters
 *
 * @param pkt - The PK Token
 * @param ruri - The redirect URI
 * @param nonce - The nonce
 * @returns A new AuthState instance
 */
export function newAuthState(pkt: PKToken, ruri: string, nonce: string): AuthState {
  const claims = JSON.parse(new TextDecoder().decode(pkt.payload)) as {
    iss: string;
    aud: string | string[];
    sub: string;
    email?: string;
    name?: string;
  };
  // Handle audience as string or array
  let audience: string;
  if (Array.isArray(claims.aud)) {
    audience = claims.aud.join(',');
  } else {
    audience = claims.aud;
  }
  const username = claims.email || claims.sub;
  const displayName = claims.name || username.split('@')[0];
  return new AuthState(
    pkt,
    claims.iss,
    audience,
    claims.sub,
    username,
    displayName,
    ruri,
    nonce
  );
}
