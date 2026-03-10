import * as jose from 'jose';
import type { PKToken } from '../pktoken/pktoken.js';
import { PublicKeyFinder, defaultPubkeyFinder } from '../discover/discover.js';

/**
 * Options for cosigner verification
 */
export interface CosignerVerifierOpts {
  /**
   * Strict specifies whether a PK Token MUST contain a signature by this cosigner
   * Defaults to true
   */
  strict?: boolean;

  /**
   * Custom function for discovering the cosigner's public key
   */
  discoverPublicKey?: PublicKeyFinder;
}

/**
 * Default cosigner verifier implementation
 *
 * Verifies that a PK Token contains a valid cosigner signature from
 * the specified issuer.
 */
export class DefaultCosignerVerifier {
  private issuer: string;
  private options: Required<CosignerVerifierOpts>;

  constructor(issuer: string, options?: CosignerVerifierOpts) {
    this.issuer = issuer;
    this.options = {
      strict: options?.strict ?? true,
      discoverPublicKey: options?.discoverPublicKey ?? defaultPubkeyFinder(),
    };
  }

  /**
   * Returns the expected cosigner issuer
   */
  getIssuer(): string {
    return this.issuer;
  }

  /**
   * Returns whether strict mode is enabled
   */
  isStrict(): boolean {
    return this.options.strict;
  }

  /**
   * Verifies the cosigner signature on a PK Token
   *
   * @param pkt - The PK Token to verify
   * @throws Error if the cosigner signature is invalid or missing (in strict mode)
   */
  async verifyCosigner(pkt: PKToken): Promise<void> {
    if (!pkt.cos) {
      throw new Error('No cosigner signature');
    }
    // Parse cosigner claims from protected headers
    const header = pkt.parseCosignerClaims();
    // Verify issuer matches
    if (this.issuer !== header.iss) {
      throw new Error(
        `Cosigner issuer (${header.iss}) doesn't match expected issuer (${this.issuer})`
      );
    }
    // Get the public key for verification
    const keyRecord = await this.options.discoverPublicKey.byKeyID(this.issuer, header.kid);
    const publicKey = keyRecord.publicKey;
    const alg = keyRecord.alg;
    // Check if expired
    const now = Math.floor(Date.now() / 1000);
    if (now > header.exp) {
      throw new Error('Cosigner signature expired');
    }
    // Verify algorithm matches
    if (header.alg !== alg) {
      throw new Error(
        `Key (kid=${header.kid}) has alg (${alg}) which doesn't match alg (${header.alg}) in protected`
      );
    }
    // Verify the signature
    const cosTokenStr = new TextDecoder().decode(pkt.cosToken);
    try {
      const key = await jose.importJWK(publicKey, alg);
      await jose.compactVerify(cosTokenStr, key);
    } catch (error) {
      throw new Error(`Failed to verify cosigner signature: ${error}`);
    }
  }
}

/**
 * Creates a new cosigner verifier
 *
 * @param issuer - The expected cosigner issuer
 * @param options - Verification options
 * @returns A new DefaultCosignerVerifier instance
 */
export function newCosignerVerifier(
  issuer: string,
  options?: CosignerVerifierOpts
): DefaultCosignerVerifier {
  return new DefaultCosignerVerifier(issuer, options);
}
