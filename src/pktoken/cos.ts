/**
 * Cosigner Claims structure
 *
 * These are the claims found in the protected headers of a cosigner (COS) signature.
 */
export interface CosignerClaims {
  /** Issuer of the cosigner token */
  iss: string;
  /** Key ID used for signing */
  kid: string;
  /** Algorithm used for signing */
  alg: string;
  /** Authentication ID (event ID) */
  eid: string;
  /** Authentication time (Unix timestamp in seconds) */
  auth_time: number;
  /** Issued at time (Unix timestamp in seconds) - may differ from auth_time due to refresh */
  iat: number;
  /** Expiration time (Unix timestamp in seconds) */
  exp: number;
  /** Redirect URI used during authentication */
  ruri: string;
  /** Nonce for binding the cosigner signature */
  nonce: string;
  /** Type field (should be 'cos') */
  typ?: string;
}

/**
 * Parses cosigner claims from a PKToken's COS protected headers
 *
 * @param cosProtectedHeaders - The protected headers from the COS signature
 * @returns The parsed cosigner claims
 * @throws Error if required fields are missing
 */
export function parseCosignerClaims(
  cosProtectedHeaders: Record<string, unknown>
): CosignerClaims {
  const claims = cosProtectedHeaders as Partial<CosignerClaims>;
  // Check that all required fields are present
  const missing: string[] = [];
  if (!claims.iss) missing.push('iss');
  if (!claims.kid) missing.push('kid');
  if (!claims.alg) missing.push('alg');
  if (!claims.eid) missing.push('eid');
  if (!claims.auth_time) missing.push('auth_time');
  if (!claims.iat) missing.push('iat');
  if (!claims.exp) missing.push('exp');
  if (!claims.ruri) missing.push('ruri');
  if (!claims.nonce) missing.push('nonce');
  if (missing.length > 0) {
    throw new Error(`Cosigner protected header missing required headers: ${missing.join(', ')}`);
  }
  return {
    iss: claims.iss!,
    kid: claims.kid!,
    alg: claims.alg!,
    eid: claims.eid!,
    auth_time: claims.auth_time!,
    iat: claims.iat!,
    exp: claims.exp!,
    ruri: claims.ruri!,
    nonce: claims.nonce!,
    typ: claims.typ,
  };
}
