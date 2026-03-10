import * as jose from 'jose';

/**
 * Public key record containing a public key and its metadata
 */
export interface PublicKeyRecord {
  publicKey: jose.JWK;
  alg: string;
  issuer: string;
}

/**
 * OIDC discovery configuration
 */
export interface OIDCDiscoveryConfig {
  issuer: string;
  jwks_uri: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  [key: string]: unknown;
}

/**
 * Fetches the OIDC discovery configuration from the well-known endpoint
 * @param issuer - The issuer URL
 * @returns The discovery configuration
 */
export async function discoverOIDCConfig(issuer: string): Promise<OIDCDiscoveryConfig> {
  const wellKnownUrl = `${issuer}/.well-known/openid-configuration`;
  const response = await fetch(wellKnownUrl);
  if (!response.ok) {
    throw new Error(`Failed to fetch OIDC config from ${wellKnownUrl}: ${response.statusText}`);
  }
  return (await response.json()) as OIDCDiscoveryConfig;
}

/**
 * Fetches the JWKS from an issuer's JWKS endpoint
 * @param issuer - The issuer URL
 * @returns The JWKS as a JSON string
 */
export async function getJwksByIssuer(issuer: string): Promise<string> {
  const config = await discoverOIDCConfig(issuer);
  const response = await fetch(config.jwks_uri);
  if (!response.ok) {
    throw new Error(`Failed to fetch JWKS from ${config.jwks_uri}: ${response.statusText}`);
  }
  return await response.text();
}

/**
 * Public key finder for locating keys by issuer and key ID
 */
export class PublicKeyFinder {
  private jwksFunc: (issuer: string) => Promise<string>;

  constructor(jwksFunc?: (issuer: string) => Promise<string>) {
    this.jwksFunc = jwksFunc || getJwksByIssuer;
  }

  /**
   * Finds a public key by issuer and key ID
   * @param issuer - The issuer URL
   * @param keyID - The key ID (kid)
   * @returns The public key record
   */
  async byKeyID(issuer: string, keyID: string): Promise<PublicKeyRecord> {
    const jwksJson = await this.jwksFunc(issuer);
    // Find the key with matching kid
    const jwksObj = JSON.parse(jwksJson) as { keys: jose.JWK[] };
    const key = jwksObj.keys.find((k) => k.kid === keyID);
    if (!key) {
      throw new Error(`Key with kid=${keyID} not found in JWKS for issuer ${issuer}`);
    }
    // Default to RS256 if alg is not specified (common for some providers)
    const alg = key.alg || 'RS256';
    return {
      publicKey: key,
      alg,
      issuer,
    };
  }

  /**
   * Finds a public key by parsing a token and extracting its kid
   * @param issuer - The issuer URL
   * @param token - The JWT token
   * @returns The public key record
   */
  async byToken(issuer: string, token: Uint8Array): Promise<PublicKeyRecord> {
    const tokenStr = new TextDecoder().decode(token);
    const header = jose.decodeProtectedHeader(tokenStr);
    if (!header.kid) {
      throw new Error('Token does not contain a kid (key ID) in its header');
    }
    return this.byKeyID(issuer, header.kid);
  }
}

/**
 * Creates a default public key finder
 */
export function defaultPubkeyFinder(): PublicKeyFinder {
  return new PublicKeyFinder();
}
