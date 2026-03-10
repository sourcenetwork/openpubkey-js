import { splitCompact, parseJWTSegment } from './oidc.js';

/**
 * Signature represents a JWS signature
 */
export interface Signature {
  protected: string; // Base64url encoded protected headers
  header?: Record<string, unknown>; // Public headers (not base64 encoded)
  signature: string; // Base64url encoded signature
}

/**
 * Protected claims found in the protected header
 */
export interface ProtectedClaims {
  alg: string; // Algorithm
  jkt?: string; // JWK Thumbprint
  kid?: string; // Key ID
  typ?: string; // Type
  cic?: string; // Client Instance Commitment
}

/**
 * JWS represents a JSON Web Signature in JSON Serialization format
 */
export interface Jws {
  payload: string; // Base64url encoded payload
  signatures: Signature[]; // Array of signatures
}

/**
 * Options for adding a signature
 */
export interface SigOpts {
  publicHeader?: Record<string, unknown>;
}

/**
 * Gets the typ (type) claim from a signature's protected headers
 * @param sig - The signature
 * @returns The type value
 */
export function getTyp(sig: Signature): string {
  const protected_claims = parseJWTSegment<ProtectedClaims>(sig.protected);
  return protected_claims.typ || '';
}

/**
 * Gets the protected claims from a signature
 * @param sig - The signature
 * @returns The protected claims
 */
export function getProtectedClaims(sig: Signature): ProtectedClaims {
  return parseJWTSegment<ProtectedClaims>(sig.protected);
}

/**
 * Adds a signature to a JWS structure from a compact JWT
 * @param jws - The JWS structure to modify
 * @param token - The compact JWT token
 * @param opts - Optional configuration
 */
export function addSignature(jws: Jws, token: Uint8Array | string, opts?: SigOpts): void {
  const [protected_header, payload, signature] = splitCompact(token);
  const protectedStr = new TextDecoder().decode(protected_header);
  const payloadStr = new TextDecoder().decode(payload);
  const signatureStr = new TextDecoder().decode(signature);
  if (jws.payload && jws.payload !== payloadStr) {
    throw new Error(
      `Payload in compact token does not match existing payload in JWS, expected=${jws.payload}, got=${payloadStr}`
    );
  }
  if (!jws.payload) {
    jws.payload = payloadStr;
  }
  const sig: Signature = {
    protected: protectedStr,
    signature: signatureStr,
  };
  if (opts?.publicHeader) {
    sig.header = opts.publicHeader;
  }
  if (!jws.signatures) {
    jws.signatures = [];
  }
  jws.signatures.push(sig);
}

/**
 * Gets a token from JWS by index
 * @param jws - The JWS structure
 * @param i - The index
 * @returns The compact JWT token
 */
export function getToken(jws: Jws, i: number): Uint8Array {
  if (i < 0 || i >= jws.signatures.length) {
    throw new Error(`No signature at index ${i}, len(signatures)=${jws.signatures.length}`);
  }
  const token = `${jws.signatures[i].protected}.${jws.payload}.${jws.signatures[i].signature}`;
  return new TextEncoder().encode(token);
}

/**
 * Gets a token from JWS by its typ (type) claim
 * @param jws - The JWS structure
 * @param typ - The type to search for
 * @returns The compact JWT token or null if not found
 */
export function getTokenByTyp(jws: Jws, typ: string): Uint8Array | null {
  const matchingTokens: Signature[] = [];
  for (const sig of jws.signatures) {
    const sigTyp = getTyp(sig);
    if (sigTyp === typ) {
      matchingTokens.push(sig);
    }
  }
  if (matchingTokens.length > 1) {
    throw new Error('More than one token found, all current token types are unique');
  }
  if (matchingTokens.length === 0) {
    return null;
  }
  const token = `${matchingTokens[0].protected}.${jws.payload}.${matchingTokens[0].signature}`;
  return new TextEncoder().encode(token);
}

/**
 * Creates a new empty JWS structure
 */
export function newJws(): Jws {
  return {
    payload: '',
    signatures: [],
  };
}
