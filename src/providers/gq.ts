import * as jose from 'jose';
import { gq256SignJWT, type GQSignOptions } from '../gq/gq.js';
import { base64DecodeForJWT } from '../util/base64.js';
import type { OpenIdProvider } from './types.js';

/**
 * Creates a GQ token from an ID token
 *
 * @param idToken - The ID token to convert to GQ
 * @param op - The OpenID provider
 * @returns The GQ-signed token
 */
export async function createGQToken(idToken: Uint8Array, op: OpenIdProvider): Promise<Uint8Array> {
  return createGQTokenAllParams(idToken, op, '', false);
}

/**
 * Creates a GQ-bound token with CIC hash
 *
 * @param idToken - The ID token to convert to GQ
 * @param op - The OpenID provider
 * @param cicHash - The client instance claims hash
 * @returns The GQ-signed token with CIC binding
 */
export async function createGQBoundToken(
  idToken: Uint8Array,
  op: OpenIdProvider,
  cicHash: string
): Promise<Uint8Array> {
  return createGQTokenAllParams(idToken, op, cicHash, true);
}

/**
 * Internal function that creates a GQ token with all parameters
 */
async function createGQTokenAllParams(
  idToken: Uint8Array,
  op: OpenIdProvider,
  cicHash: string,
  gqCommitment: boolean
): Promise<Uint8Array> {
  if (cicHash !== '' && !gqCommitment) {
    throw new Error(
      'Misconfiguration: cicHash is set but gqCommitment is false. Set gqCommitment to true to include cicHash in the GQ signature'
    );
  }
  // Verify the ID token is RS256
  const idTokenStr = new TextDecoder().decode(idToken);
  const parts = idTokenStr.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }
  const headerJSON = new TextDecoder().decode(base64DecodeForJWT(parts[0]));
  const headers = JSON.parse(headerJSON) as { alg?: string; kid?: string };
  if (headers.alg !== 'RS256') {
    throw new Error(`GQ signatures require ID Token signed with RS256, got: ${headers.alg}`);
  }
  // Get the OP's public key
  const opKey = await op.publicKeyByToken(idToken);
  if (opKey.alg !== 'RS256') {
    throw new Error(`GQ signatures require RSA key, got: ${opKey.alg}`);
  }
  // Create JKT (JWK thumbprint) of the public key
  const jwk = opKey.publicKey;
  const jkt = await createJkt(jwk);
  // Build GQ sign options
  const opts: GQSignOptions = {
    extraClaims: {
      jkt,
    },
  };
  // Add CIC hash if provided
  if (cicHash !== '') {
    opts.extraClaims!.cic = cicHash;
  }
  // Sign with GQ
  return gq256SignJWT(jwk, idToken, opts);
}

/**
 * Creates a JWK thumbprint (jkt) for the given public key
 */
async function createJkt(publicKey: jose.JWK): Promise<string> {
  const thumbprint = await jose.calculateJwkThumbprint(publicKey, 'sha256');
  return thumbprint;
}
