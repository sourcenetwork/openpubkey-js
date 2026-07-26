import * as jose from 'jose';
import type { PKToken } from './pktoken.js';
import type { VerifyOptions } from './osm.js';
import { base64UrlEncode } from '../util/base64.js';
import { webCryptoSignAlgorithm } from '../util/crypto.js';

// Browser type declarations
declare const crypto: { subtle: SubtleCrypto };

export type { VerifyOptions };

/**
 * Creates a signed message (OSM - OpenPubkey Signed Message) using a PK Token (Browser version)
 *
 * OSMs are a type of JWS (JSON Web Signature) that commit to the PK Token
 * which was used to generate the OSM. This provides proof-of-possession.
 *
 * The OSM headers include:
 * - alg: The algorithm from the CIC
 * - kid: The hash of the PK Token (proves which token was used)
 * - typ: "osm" (identifies this as an OpenPubkey Signed Message)
 *
 * This is the browser-compatible version that works with Web Crypto API CryptoKey objects.
 *
 * @param pkt - The PK Token to use for signing
 * @param content - The message content to sign
 * @param signer - The browser CryptoKey to sign with (must match the public key in the PK Token's CIC)
 * @returns The signed message as a JWS compact serialization
 */
export async function newSignedMessageBrowser(
  pkt: PKToken,
  content: Uint8Array,
  signer: CryptoKey
): Promise<Uint8Array> {
  // Get CIC values from the PK Token
  const cic = pkt.getCicValues();
  if (!cic) {
    throw new Error('PK Token does not contain CIC values');
  }
  // Get the hash of the PK Token (used as kid)
  const pktHash = await pkt.hash();
  // Get the algorithm from the CIC public key
  const publicKey = cic.getPublicKey();
  const algorithm = publicKey.alg;
  if (!algorithm) {
    throw new Error('CIC public key does not specify an algorithm');
  }
  const protectedHeader = base64UrlEncode(
    JSON.stringify({
      alg: algorithm,
      kid: pktHash,
      typ: 'osm',
    })
  );
  const payload = base64UrlEncode(content);
  const signingInput = `${protectedHeader}.${payload}`;
  const signature = await crypto.subtle.sign(
    webCryptoSignAlgorithm(algorithm),
    signer,
    new TextEncoder().encode(signingInput)
  );
  const jws = `${signingInput}.${base64UrlEncode(new Uint8Array(signature))}`;
  return new TextEncoder().encode(jws);
}

/**
 * Verifies an OSM (OpenPubkey Signed Message) using the public key in a PK Token
 *
 * This verifies that:
 * 1. The OSM has the correct headers (typ, alg, kid)
 * 2. The kid matches the hash of this PK Token
 * 3. The signature is valid using the public key from the PK Token's CIC
 *
 * Note: This does NOT verify that the PK Token itself is valid.
 * The PK Token should always be verified first before calling this function.
 *
 * @param pkt - The PK Token containing the public key to verify with
 * @param osm - The signed message to verify
 * @param options - Verification options
 * @returns The verified message content (payload)
 */
export async function verifySignedMessageBrowser(
  pkt: PKToken,
  osm: Uint8Array,
  options?: VerifyOptions
): Promise<Uint8Array> {
  // Default options
  const opts = {
    typ: 'osm',
    ...options,
  };
  // Get CIC values from the PK Token
  const cic = pkt.getCicValues();
  if (!cic) {
    throw new Error('PK Token does not contain CIC values');
  }
  // Parse the JWS
  const osmStr = new TextDecoder().decode(osm);
  const parts = osmStr.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWS format');
  }
  // Decode the protected header
  const protectedHeaderBytes = jose.base64url.decode(parts[0]);
  const protectedHeader = JSON.parse(new TextDecoder().decode(protectedHeaderBytes));
  // Verify typ header
  if (!protectedHeader.typ) {
    throw new Error('Missing required header `typ`');
  }
  if (protectedHeader.typ !== opts.typ) {
    throw new Error(
      `Incorrect "typ" header, expected "${opts.typ}" but received "${protectedHeader.typ}"`
    );
  }
  // Verify alg header matches CIC
  const publicKey = cic.getPublicKey();
  const expectedAlg = publicKey.alg;
  if (protectedHeader.alg !== expectedAlg) {
    throw new Error(
      `Incorrect "alg" header, expected ${expectedAlg} but received ${protectedHeader.alg}`
    );
  }
  // Verify kid header matches PK Token hash
  if (!protectedHeader.kid) {
    throw new Error('Missing required header `kid`');
  }
  // pktHash is already a string (base64url encoded hash)
  const pktHash = await pkt.hash();
  if (protectedHeader.kid !== pktHash) {
    throw new Error(
      `Incorrect "kid" header, expected ${pktHash} but received ${protectedHeader.kid}`
    );
  }
  // Import the public key from CIC
  const key = await jose.importJWK(publicKey, expectedAlg);
  // Verify the signature
  const { payload } = await jose.compactVerify(osmStr, key);
  return new Uint8Array(payload);
}
