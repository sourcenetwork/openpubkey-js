import type * as jose from 'jose';
import type { PKToken } from '../pktoken/pktoken.js';
import { parseOidcClaims } from '../oidc/oidc.js';

/**
 * X.509 Certificate Template
 *
 * Contains the data needed to create an X.509 certificate from a PK Token.
 * Use with node-forge or similar library to create actual certificates.
 */
export interface X509Template {
  subject: string;
  issuer: string;
  publicKeyJwk: jose.JWK;
  pkTokenJson: string;
  notBefore: Date;
  notAfter: Date;
}

/**
 * Creates an X.509 certificate template from a PK Token.
 *
 * This extracts the necessary data to create an X.509 certificate:
 * - OP 'sub' claim -> CN field
 * - OP 'iss' claim -> issuer field
 * - User public key from CIC
 * - Serialized PK Token for embedding
 *
 * To create an actual X.509 certificate, use this template with
 * a library like node-forge or OpenSSL bindings.
 */
export async function pktToX509Template(pkt: PKToken): Promise<X509Template> {
  const pktJson = JSON.stringify(pkt);
  const claims = parseOidcClaims(JSON.parse(new TextDecoder().decode(pkt.payload)));
  const cic = pkt.getCicValues();
  if (!cic) {
    throw new Error('PK Token does not contain CIC values');
  }
  const publicKeyJwk = cic.getPublicKey();
  return {
    subject: claims.sub,
    issuer: claims.iss,
    publicKeyJwk,
    pkTokenJson: pktJson,
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
  };
}
