/**
 * Initial MFA authentication message
 */
export interface InitMFAAuth {
  /** Cosigner issuer URL */
  iss: string;
  /** Redirect URI for callback */
  ruri: string;
  /** Unix timestamp when signed */
  time: number;
  /** Unique nonce for this request */
  nonce: string;
}
