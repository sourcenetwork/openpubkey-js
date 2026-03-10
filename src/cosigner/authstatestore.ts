import type { PKToken } from '../pktoken/pktoken.js';
import type { AuthState } from './authstate.js';

/**
 * AuthStateStore interface for managing authentication session state
 *
 * This interface defines the operations needed to store and retrieve
 * authentication state during the cosigner MFA flow.
 */
export interface AuthStateStore {
  /**
   * Creates a new authentication session
   *
   * @param pkt - The PK Token
   * @param ruri - The redirect URI
   * @param nonce - The nonce
   * @returns The authentication session ID
   */
  createNewAuthSession(pkt: PKToken, ruri: string, nonce: string): Promise<string>;

  /**
   * Looks up an authentication state by ID
   *
   * @param authID - The authentication session ID
   * @returns The auth state if found, or undefined
   */
  lookupAuthState(authID: string): Promise<AuthState | undefined>;

  /**
   * Updates an existing authentication state
   *
   * @param authID - The authentication session ID
   * @param authState - The updated auth state
   */
  updateAuthState(authID: string, authState: AuthState): Promise<void>;

  /**
   * Creates an authcode for an authentication session
   *
   * @param authID - The authentication session ID
   * @returns The authcode
   */
  createAuthcode(authID: string): Promise<string>;

  /**
   * Redeems an authcode and returns the authentication state
   *
   * @param authcode - The authcode to redeem
   * @returns The auth state and auth ID
   */
  redeemAuthcode(authcode: string): Promise<{ authState: AuthState; authID: string }>;
}
