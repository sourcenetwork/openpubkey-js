import * as jose from 'jose';
import type { PKToken } from '../pktoken/pktoken.js';
import { type OpenIdProvider, type RefreshableOpenIdProvider, isRefreshable } from '../providers/types.js';
import type { Claims } from '../pktoken/clientinstance/claims.js';

/**
 * Expiration policy configuration
 */
export interface ExpirationPolicyConfig {
  maxAge: number; // milliseconds
  checkMaxAge: boolean;
  checkExpClaim: boolean;
  checkRefreshed: boolean;
}

/**
 * Expiration policies enum
 */
export const ExpirationPolicies = {
  OIDC: {
    maxAge: 0,
    checkMaxAge: false,
    checkExpClaim: true,
    checkRefreshed: false,
  } as ExpirationPolicyConfig,
  OIDC_REFRESHED: {
    maxAge: 0,
    checkMaxAge: false,
    checkExpClaim: false,
    checkRefreshed: true,
  } as ExpirationPolicyConfig,
  MAX_AGE_12HOURS: {
    maxAge: 12 * 60 * 60 * 1000,
    checkMaxAge: true,
    checkExpClaim: false,
    checkRefreshed: false,
  } as ExpirationPolicyConfig,
  MAX_AGE_24HOURS: {
    maxAge: 24 * 60 * 60 * 1000,
    checkMaxAge: true,
    checkExpClaim: false,
    checkRefreshed: false,
  } as ExpirationPolicyConfig,
  MAX_AGE_48HOURS: {
    maxAge: 2 * 24 * 60 * 60 * 1000,
    checkMaxAge: true,
    checkExpClaim: false,
    checkRefreshed: false,
  } as ExpirationPolicyConfig,
  MAX_AGE_1WEEK: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    checkMaxAge: true,
    checkExpClaim: false,
    checkRefreshed: false,
  } as ExpirationPolicyConfig,
  NEVER_EXPIRE: {
    maxAge: 0,
    checkMaxAge: false,
    checkExpClaim: false,
    checkRefreshed: false,
  } as ExpirationPolicyConfig,
};

/**
 * Verifier options
 */
export interface VerifierOptions {
  expirationPolicy?: ExpirationPolicyConfig;
  requireRefreshedIDToken?: boolean;
}

/**
 * Additional check function for PK Token verification
 */
export type Check = (pkt: PKToken) => Promise<void>;

/**
 * Provider verifier interface - providers must implement this for verification
 */
export interface ProviderVerifier {
  issuer(): string;
  verifyIDToken(idt: Uint8Array, cic: Claims): Promise<void>;
  publicKeyByToken(token: Uint8Array): Promise<jose.JWK>;
}

/**
 * PKToken Verifier
 *
 * Verifies PK Tokens by checking signatures, claims, and expiration
 */
export class Verifier {
  private providers: Map<string, ProviderVerifier>;
  private expirationPolicy: ExpirationPolicyConfig;
  private requireRefreshedIDToken: boolean;

  private constructor(providers: ProviderVerifier[], options?: VerifierOptions) {
    this.providers = new Map();
    for (const pv of providers) {
      this.providers.set(pv.issuer(), pv);
    }
    this.expirationPolicy = options?.expirationPolicy || ExpirationPolicies.MAX_AGE_24HOURS;
    this.requireRefreshedIDToken = options?.requireRefreshedIDToken || false;
  }

  /**
   * Creates a new verifier from a single provider
   */
  static async newVerifier(
    provider: OpenIdProvider,
    options?: VerifierOptions
  ): Promise<Verifier> {
    const pv: ProviderVerifier = {
      issuer: () => provider.issuer(),
      verifyIDToken: (idt, cic) => provider.verifyIDToken(idt, cic),
      publicKeyByToken: async (token) => {
        const record = await provider.publicKeyByToken(token);
        return record.publicKey;
      },
    };
    if (isRefreshable(provider)) {
      (pv as ProviderVerifier & Pick<RefreshableOpenIdProvider, 'verifyRefreshedIDToken'>)
        .verifyRefreshedIDToken = (origIdt, reIdt) => provider.verifyRefreshedIDToken(origIdt, reIdt);
    }
    return new Verifier([pv], options);
  }

  /**
   * Creates a new verifier from multiple providers
   */
  static async newFromMany(
    providers: ProviderVerifier[],
    options?: VerifierOptions
  ): Promise<Verifier> {
    return new Verifier(providers, options);
  }

  /**
   * Verifies a PK Token
   * @param pkt - The PK Token to verify
   * @param extraChecks - Additional verification checks
   */
  async verifyPKToken(pkt: PKToken, ...extraChecks: Check[]): Promise<void> {
    // Verify CIC signature first (cheap check)
    await this.verifyCicSignature(pkt);
    // Get issuer and find provider
    const issuer = pkt.issuer();
    const providerVerifier = this.providers.get(issuer);
    if (!providerVerifier) {
      const knownIssuers = Array.from(this.providers.keys());
      throw new Error(
        `Unrecognized issuer: ${issuer}, known issuers: ${knownIssuers.join(', ')}`
      );
    }
    // Get CIC values
    const cic = pkt.getCicValues();
    // Verify ID Token (OP signature)
    if (!pkt.opToken) {
      throw new Error('Missing OP token');
    }
    await providerVerifier.verifyIDToken(pkt.opToken, cic);
    // Verify expiration
    await this.checkExpiration(pkt, this.expirationPolicy);
    // If required, verify refreshed ID token
    if (this.requireRefreshedIDToken) {
      if (!pkt.freshIDToken) {
        throw new Error('No refreshed ID Token set but it is required');
      }
      const verifyRefreshed = (providerVerifier as ProviderVerifier & { verifyRefreshedIDToken?: RefreshableOpenIdProvider['verifyRefreshedIDToken'] }).verifyRefreshedIDToken;
      if (!verifyRefreshed) {
        throw new Error(
          `Refreshed ID Token verification required but provider (issuer=${issuer}) does not support it`
        );
      }
      await verifyRefreshed(pkt.opToken, pkt.freshIDToken);
    }
    // Run extra checks
    for (const check of extraChecks) {
      await check(pkt);
    }
  }

  /**
   * Verifies the CIC signature using the public key embedded in the CIC
   */
  private async verifyCicSignature(pkt: PKToken): Promise<void> {
    if (!pkt.cicToken) {
      throw new Error('Missing CIC token');
    }
    const cic = pkt.getCicValues();
    const publicKey = cic.getPublicKey();
    try {
      // Import the JWK as a crypto key
      const key = await jose.importJWK(publicKey);
      // Verify the JWT signature
      const tokenStr = new TextDecoder().decode(pkt.cicToken);
      await jose.jwtVerify(tokenStr, key);
    } catch (error) {
      throw new Error(`Failed to verify CIC signature: ${error}`);
    }
  }

  /**
   * Checks expiration based on the expiration policy
   */
  private async checkExpiration(
    pkt: PKToken,
    policy: ExpirationPolicyConfig
  ): Promise<void> {
    const payloadStr = new TextDecoder().decode(pkt.payload);
    const claims = JSON.parse(payloadStr) as { exp?: number; iat?: number };
    // Check exp claim if required
    if (policy.checkExpClaim) {
      const expired = await this.verifyNotExpired(claims.exp);
      if (expired) {
        throw new Error(`ID Token has expired (exp=${claims.exp})`);
      }
    }
    // Check refreshed token if required
    if (policy.checkRefreshed) {
      const expired = await this.verifyNotExpired(claims.exp);
      if (expired) {
        if (!pkt.freshIDToken) {
          throw new Error('ID token is expired and no refresh token found');
        }
        // Parse fresh ID token
        const freshTokenStr = new TextDecoder().decode(pkt.freshIDToken);
        const freshClaims = jose.decodeJwt(freshTokenStr);
        const freshExpired = await this.verifyNotExpired(freshClaims.exp as number);
        if (freshExpired) {
          throw new Error('Refreshed ID token has also expired');
        }
      }
    }
    // Check max age if required
    if (policy.checkMaxAge && policy.maxAge > 0) {
      const maxAgeSeconds = policy.maxAge / 1000;
      await this.checkMaxAge(claims.iat, maxAgeSeconds);
    }
  }

  /**
   * Verifies token is not expired based on exp claim
   * @returns true if expired, false if still valid
   */
  private async verifyNotExpired(expiration?: number): Promise<boolean> {
    if (!expiration) {
      throw new Error('Missing expiration claim');
    }
    if (expiration < 0) {
      throw new Error(`Expiration must be greater than zero (exp=${expiration})`);
    }
    const now = Math.floor(Date.now() / 1000);
    return now > expiration;
  }

  /**
   * Checks max age of token based on iat claim
   */
  private async checkMaxAge(issuedAt?: number, maxAgeSeconds?: number): Promise<void> {
    if (!issuedAt) {
      throw new Error('Missing issuedAt claim');
    }
    if (issuedAt < 0) {
      throw new Error(`IssuedAt must be greater than zero (iat=${issuedAt})`);
    }
    if (!maxAgeSeconds || maxAgeSeconds <= 0) {
      throw new Error(`MaxAge must be greater than zero (maxAge=${maxAgeSeconds})`);
    }
    if (issuedAt + maxAgeSeconds < issuedAt) {
      throw new Error(`Invalid values (iat=${issuedAt}, maxAge=${maxAgeSeconds})`);
    }
    const expirationTime = issuedAt + maxAgeSeconds;
    const now = Math.floor(Date.now() / 1000);
    if (now > expirationTime) {
      throw new Error(
        `PK token has expired based on maxAge (iat=${issuedAt}, maxAge=${maxAgeSeconds}, expired at=${expirationTime})`
      );
    }
  }
}
