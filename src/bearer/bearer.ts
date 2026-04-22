/**
 * buildBearerToken — produce a compact JWS bearer token in the format trust-api expects.
 *
 * The token is a signed JWT whose payload carries:
 *   - iss:                the issuer DID (usually did:key:z... matching the signer's public key)
 *   - authorized_account: optional SourceHub bech32 account for feegranted broadcasts
 *   - pkt:                optional OpenPubkey PKToken, compact-serialized + base64url-encoded
 *   - provider_token:     optional free-form string passed through by the server
 *   - iat, exp:           standard Unix timestamp claims
 *
 * The signer can be a WebCrypto CryptoKey (browser) or a Node crypto.KeyObject. The signing
 * algorithm is either passed explicitly or inferred from the key material (ES256 / ES256K /
 * EdDSA / RS256). jose handles both key types transparently.
 */

import * as jose from 'jose';
import type * as nodeCryptoModule from 'crypto';
import { base64UrlEncode } from '../util/base64.js';
import { PKToken } from '../pktoken/pktoken.js';

export interface BuildBearerTokenOptions {
  /** DID of the signer, e.g. `did:key:z...`. Required. */
  iss: string;
  /** SourceHub account authorised to broadcast on behalf of the DID. Omit for read-only tokens. */
  authorizedAccount?: string;
  /** OpenPubkey PKToken bound to the signer, if the caller is signing via Google OAuth. */
  pkToken?: PKToken;
  /** Opaque per-provider context string the server stores verbatim. */
  providerToken?: string;
  /** Lifetime in seconds; defaults to 600 (10 minutes) to match the Go CLI. */
  expiresInSec?: number;
  /** Override the signing algorithm. Inferred from `signer` if omitted. */
  algorithm?: BearerAlgorithm;
  /** Override `iat`; defaults to `Math.floor(Date.now()/1000)`. Mostly useful for tests. */
  iat?: number;
}

export type BearerAlgorithm = 'ES256' | 'ES256K' | 'EdDSA' | 'RS256';

type Signer = CryptoKey | nodeCryptoModule.KeyObject;

const DEFAULT_EXPIRES_IN_SEC = 600;

export async function buildBearerToken(
  signer: Signer,
  opts: BuildBearerTokenOptions
): Promise<string> {
  if (!opts.iss) {
    throw new Error('buildBearerToken: iss is required');
  }

  const alg = opts.algorithm ?? inferAlgorithm(signer);
  const iat = opts.iat ?? Math.floor(Date.now() / 1000);
  const exp = iat + (opts.expiresInSec ?? DEFAULT_EXPIRES_IN_SEC);

  const payload: Record<string, unknown> = {
    iss: opts.iss,
    iat,
    exp,
  };
  if (opts.authorizedAccount !== undefined) {
    payload.authorized_account = opts.authorizedAccount;
  }
  if (opts.providerToken !== undefined) {
    payload.provider_token = opts.providerToken;
  }
  if (opts.pkToken) {
    const pktCompact = await opts.pkToken.compact();
    payload.pkt = base64UrlEncode(pktCompact);
  }

  return new jose.SignJWT(payload)
    .setProtectedHeader({ alg, typ: 'JWT' })
    .sign(signer as jose.KeyLike);
}

/**
 * inferAlgorithm picks the JWS alg from a signer's key type/curve.
 *
 * Browser `CryptoKey` carries an `algorithm` descriptor (ECDSA + P-256 → ES256, RSASSA-PKCS1-v1_5 →
 * RS256, Ed25519 → EdDSA). Node `KeyObject` carries `asymmetricKeyType`/`asymmetricKeyDetails`.
 * P-256K (secp256k1) is recognised but the library currently doesn't generate it — callers that
 * bring their own secp256k1 signer will hit this branch.
 */
function inferAlgorithm(signer: Signer): BearerAlgorithm {
  // Browser CryptoKey: check the Web Crypto algorithm descriptor.
  if (typeof (signer as CryptoKey).algorithm === 'object' && (signer as CryptoKey).algorithm !== null) {
    const ck = signer as CryptoKey;
    const descriptor = ck.algorithm as { name?: string; namedCurve?: string };
    if (descriptor.name === 'ECDSA') {
      if (descriptor.namedCurve === 'P-256') return 'ES256';
      if (descriptor.namedCurve === 'P-256K' || descriptor.namedCurve === 'secp256k1') return 'ES256K';
      throw new Error(`buildBearerToken: unsupported ECDSA curve ${descriptor.namedCurve}`);
    }
    if (descriptor.name === 'RSASSA-PKCS1-v1_5') return 'RS256';
    if (descriptor.name === 'Ed25519') return 'EdDSA';
    throw new Error(`buildBearerToken: cannot infer algorithm from CryptoKey "${descriptor.name}"`);
  }

  // Node KeyObject.
  const ko = signer as nodeCryptoModule.KeyObject;
  if (typeof ko.asymmetricKeyType === 'string') {
    switch (ko.asymmetricKeyType) {
      case 'ec': {
        const curve = (ko.asymmetricKeyDetails?.namedCurve ?? '').toLowerCase();
        if (curve === 'prime256v1' || curve === 'p-256') return 'ES256';
        if (curve === 'secp256k1') return 'ES256K';
        throw new Error(`buildBearerToken: unsupported EC curve ${curve}`);
      }
      case 'rsa':
        return 'RS256';
      case 'ed25519':
        return 'EdDSA';
      default:
        throw new Error(`buildBearerToken: unsupported key type ${ko.asymmetricKeyType}`);
    }
  }

  throw new Error('buildBearerToken: could not infer algorithm — pass opts.algorithm explicitly');
}
