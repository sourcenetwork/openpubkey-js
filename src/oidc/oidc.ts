import { base64DecodeForJWT } from '../util/base64.js';

/**
 * OidcClaims represents the standard OpenID Connect claims
 */
export interface OidcClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  email?: string;
  nonce?: string;
  preferred_username?: string;
  given_name?: string;
  family_name?: string;
  groups?: string[];
  scopes?: string[];
}

/**
 * Parse OIDC claims from JSON, preserving the audience type (string or array)
 */
export function parseOidcClaims(data: unknown): OidcClaims {
  const obj = data as Record<string, unknown>;
  return {
    iss: obj.iss as string,
    sub: obj.sub as string,
    aud: obj.aud as string | string[],
    exp: obj.exp as number,
    iat: obj.iat as number,
    email: obj.email as string | undefined,
    nonce: obj.nonce as string | undefined,
    preferred_username: obj.preferred_username as string | undefined,
    given_name: obj.given_name as string | undefined,
    family_name: obj.family_name as string | undefined,
    groups: obj.groups as string[] | undefined,
    scopes: obj.scopes as string[] | undefined,
  };
}

/**
 * Splits a JWT into its three parts: protected headers, payload, and signature
 * @param src - The JWT in compact format
 * @returns Tuple of [protected, payload, signature]
 */
export function splitCompact(src: Uint8Array | string): [Uint8Array, Uint8Array, Uint8Array] {
  const srcStr = typeof src === 'string' ? src : new TextDecoder().decode(src);
  const parts = srcStr.split('.');
  if (parts.length !== 3) {
    throw new Error(`Invalid number of segments: expected 3, got ${parts.length}`);
  }
  return [
    new TextEncoder().encode(parts[0]),
    new TextEncoder().encode(parts[1]),
    new TextEncoder().encode(parts[2]),
  ];
}

/**
 * Parses a JWT segment (base64url encoded) into an object
 * @param segment - The base64url encoded segment
 * @returns The parsed object
 */
export function parseJWTSegment<T = unknown>(segment: Uint8Array | string): T {
  const segmentBytes = typeof segment === 'string' ? new TextEncoder().encode(segment) : segment;
  const segmentJSON = base64DecodeForJWT(segmentBytes);
  const jsonStr = new TextDecoder().decode(segmentJSON);
  return JSON.parse(jsonStr) as T;
}
