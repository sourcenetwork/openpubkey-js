import type * as crypto from 'crypto';
import * as jose from 'jose';
import {
  type Jws,
  type Signature,
  addSignature as addJwsSignature,
  newJws,
  getProtectedClaims,
} from '../oidc/jws.js';
import { splitCompact, parseJWTSegment } from '../oidc/oidc.js';
import { base64EncodeForJWT } from '../util/base64.js';
import { bytesEqual } from '../util/bytes.js';
import { b64SHA3_256 } from '../util/crypto.js';
import { Claims } from './clientinstance/claims.js';
import { compactPKToken, splitCompactPKToken } from './compact.js';
import { parseCosignerClaims, type CosignerClaims } from './cos.js';

/**
 * Signature types in a PK Token
 */
export enum SignatureType {
  OIDC = 'JWT',
  CIC = 'CIC',
  COS = 'COS',
}

/**
 * PKToken represents an OpenPubKey token
 */
export class PKToken {
  private raw?: Uint8Array; // Original raw representation

  payload: Uint8Array; // Decoded payload
  op?: Signature; // Provider Signature
  cic?: Signature; // Client Signature
  cos?: Signature; // Cosigner Signature

  // Keep tokens as byte arrays since unmarshalled values can no longer be verified
  opToken?: Uint8Array; // ID Token signed by OP
  cicToken?: Uint8Array; // Token signed by Client
  cosToken?: Uint8Array; // Token signed by Cosigner

  freshIDToken?: Uint8Array; // Refreshed ID Token (for POP authentication)

  constructor() {
    this.payload = new Uint8Array();
  }

  /**
   * Creates a new PKToken from an ID Token and CIC Token
   * @param idToken - The ID Token from the OpenID Provider
   * @param cicToken - The CIC Token signed by the client
   * @returns A new PKToken instance
   */
  static async newPKToken(idToken: Uint8Array, cicToken: Uint8Array): Promise<PKToken> {
    const pkt = new PKToken();
    await pkt.addSignature(idToken, SignatureType.OIDC);
    await pkt.addSignature(cicToken, SignatureType.CIC);
    return pkt;
  }

  /**
   * Creates a PKToken from a compact representation
   * @param pktCom - The compact PKToken bytes
   * @returns A new PKToken instance
   */
  static async newFromCompact(pktCom: Uint8Array): Promise<PKToken> {
    const [tokens, freshIDToken] = splitCompactPKToken(pktCom);
    const pkt = new PKToken();
    for (const token of tokens) {
      const [protectedBytes] = splitCompact(token);
      const protected_claims = parseJWTSegment(protectedBytes);
      const typClaim = (protected_claims as { typ?: string }).typ;
      let sigType: SignatureType;
      if (!typClaim || typClaim === '') {
        sigType = SignatureType.OIDC;
      } else {
        sigType = typClaim as SignatureType;
      }
      await pkt.addSignature(token, sigType);
    }
    pkt.freshIDToken = freshIDToken || undefined;
    return pkt;
  }

  /**
   * Returns the issuer (iss) of the ID Token
   */
  issuer(): string {
    const claims = JSON.parse(new TextDecoder().decode(this.payload)) as { iss?: string };
    if (!claims.iss) {
      throw new Error('Malformatted PK token claims: missing iss');
    }
    return claims.iss;
  }

  /**
   * Returns the audience (aud) of the ID Token
   */
  audience(): string | string[] {
    const claims = JSON.parse(new TextDecoder().decode(this.payload)) as { aud?: string | string[] };
    if (!claims.aud) {
      throw new Error('Malformatted PK token claims: missing aud');
    }
    return claims.aud;
  }

  /**
   * Returns the subject (sub) of the ID Token
   */
  subject(): string {
    const claims = JSON.parse(new TextDecoder().decode(this.payload)) as { sub?: string };
    if (!claims.sub) {
      throw new Error('Malformatted PK token claims: missing sub');
    }
    return claims.sub;
  }

  /**
   * Returns the identity string (sub + issuer)
   */
  identityString(): string {
    return `${this.subject()} ${this.issuer()}`;
  }

  /**
   * Signs the PK Token payload and returns a JWT
   * @param signer - The signing key
   * @param algorithm - The algorithm to use
   * @param protectedHeaders - Additional protected headers
   * @returns The signed JWT
   */
  async signToken(
    signer: crypto.KeyObject,
    algorithm: string,
    protectedHeaders: Record<string, unknown>
  ): Promise<Uint8Array> {
    const payloadObj = JSON.parse(new TextDecoder().decode(this.payload));
    const jwt = await new jose.SignJWT(payloadObj)
      .setProtectedHeader({ alg: algorithm, ...protectedHeaders })
      .sign(signer);
    return new TextEncoder().encode(jwt);
  }

  /**
   * Adds a signature to the PKToken
   * @param token - The token bytes
   * @param sigType - The signature type
   */
  async addSignature(token: Uint8Array, sigType: SignatureType): Promise<void> {
    // Parse the token using jose
    const tokenStr = new TextDecoder().decode(token);
    const protectedHeader = jose.decodeProtectedHeader(tokenStr);
    // Get payload bytes
    const [, payloadBytes] = splitCompact(token);
    const payloadDecoded = jose.base64url.decode(new TextDecoder().decode(payloadBytes));
    // If no payload set, use this one, otherwise verify they match
    if (this.payload.length === 0) {
      this.payload = payloadDecoded;
    } else {
      if (!bytesEqual(this.payload, payloadDecoded)) {
        throw new Error('Payload in token does not match existing payload in PK Token');
      }
    }
    // Create signature object
    const [protectedStr, , sigStr] = new TextDecoder().decode(token).split('.');
    const sig: Signature = {
      protected: protectedStr,
      signature: sigStr,
    };
    // Verify typ claim for CIC and COS
    if (sigType === SignatureType.CIC || sigType === SignatureType.COS) {
      const typFound = (protectedHeader as jose.JWTHeaderParameters).typ as string | undefined;
      if (!typFound) {
        throw new Error("Required 'typ' claim not found in protected header");
      }
      if (typFound !== sigType) {
        throw new Error(
          `Incorrect 'typ' claim in protected, expected ${sigType}, got ${typFound}`
        );
      }
    }
    // Assign to appropriate field
    switch (sigType) {
      case SignatureType.OIDC:
        this.op = sig;
        this.opToken = token;
        break;
      case SignatureType.CIC:
        this.cic = sig;
        this.cicToken = token;
        break;
      case SignatureType.COS:
        this.cos = sig;
        this.cosToken = token;
        break;
      default:
        throw new Error(`Unrecognized signature type: ${sigType}`);
    }
  }

  /**
   * Gets the provider algorithm from the OP signature
   */
  providerAlgorithm(): string | null {
    if (!this.op) return null;
    const claims = getProtectedClaims(this.op);
    return claims.alg || null;
  }

  /**
   * Gets the CIC values from the CIC signature
   */
  getCicValues(): Claims {
    if (!this.cic) {
      throw new Error('No CIC signature present');
    }
    const protectedClaims = parseJWTSegment(this.cic.protected);
    return Claims.parseClaims(protectedClaims as Record<string, unknown>);
  }

  /**
   * Parses and returns the cosigner claims from the COS signature
   * @returns The cosigner claims
   * @throws Error if no COS signature is present or required fields are missing
   */
  parseCosignerClaims(): CosignerClaims {
    if (!this.cos) {
      throw new Error('No COS signature present');
    }
    const protectedClaims = parseJWTSegment(this.cos.protected);
    return parseCosignerClaims(protectedClaims as Record<string, unknown>);
  }

  /**
   * Returns a hash of the PK Token
   */
  async hash(): Promise<string> {
    let message: Uint8Array;
    if (this.raw) {
      message = this.raw;
    } else {
      const jsonStr = JSON.stringify(await this.toJSON());
      message = new TextEncoder().encode(jsonStr);
    }
    const hash = await b64SHA3_256(message);
    return new TextDecoder().decode(hash);
  }

  /**
   * Serializes the PK Token to compact format
   */
  async compact(): Promise<Uint8Array> {
    const tokens: Uint8Array[] = [];
    if (this.opToken) tokens.push(this.opToken);
    if (this.cicToken) tokens.push(this.cicToken);
    if (this.cosToken) tokens.push(this.cosToken);
    return compactPKToken(tokens, this.freshIDToken);
  }

  /**
   * Marshals the PKToken to JSON (JWS format)
   */
  async toJSON(): Promise<Jws> {
    const rawJws = newJws();
    rawJws.payload = new TextDecoder().decode(base64EncodeForJWT(this.payload));
    if (this.opToken) {
      const publicHeader = this.op?.header;
      addJwsSignature(rawJws, this.opToken, { publicHeader });
    }
    if (this.cicToken) {
      addJwsSignature(rawJws, this.cicToken);
    }
    if (this.cosToken) {
      addJwsSignature(rawJws, this.cosToken);
    }
    return rawJws;
  }

  /**
   * Creates a deep copy of the PKToken
   */
  async deepCopy(): Promise<PKToken> {
    const pktJson = await this.toJSON();
    const jsonStr = JSON.stringify(pktJson);
    return PKToken.fromJSON(jsonStr);
  }

  /**
   * Creates a PKToken from JSON
   */
  static async fromJSON(jsonStr: string): Promise<PKToken> {
    const rawJws = JSON.parse(jsonStr) as Jws;
    const pkt = new PKToken();
    // Decode payload
    pkt.payload = jose.base64url.decode(rawJws.payload);
    let opCount = 0;
    let cicCount = 0;
    let cosCount = 0;
    for (let i = 0; i < rawJws.signatures.length; i++) {
      const sig = rawJws.signatures[i];
      // Reconstruct compact token
      const token = `${sig.protected}.${rawJws.payload}.${sig.signature}`;
      const tokenBytes = new TextEncoder().encode(token);
      // Determine signature type
      const protectedClaims = parseJWTSegment(sig.protected);
      const typClaim = (protectedClaims as { typ?: string }).typ;
      let sigType: SignatureType;
      if (!typClaim) {
        sigType = SignatureType.OIDC;
      } else {
        sigType = typClaim as SignatureType;
      }
      switch (sigType) {
        case SignatureType.OIDC:
          opCount++;
          pkt.op = sig;
          pkt.opToken = tokenBytes;
          break;
        case SignatureType.CIC:
          cicCount++;
          pkt.cic = sig;
          pkt.cicToken = tokenBytes;
          break;
        case SignatureType.COS:
          cosCount++;
          pkt.cos = sig;
          pkt.cosToken = tokenBytes;
          break;
        default:
          throw new Error(`Unrecognized signature type: ${sigType}`);
      }
    }
    // Validate signature counts
    if (opCount === 0) {
      throw new Error('At least one signature of type "JWT" is required');
    } else if (opCount > 1) {
      throw new Error(`Only one signature of type "JWT" is allowed, found ${opCount}`);
    }
    if (cicCount === 0) {
      throw new Error('At least one signature of type "CIC" is required');
    } else if (cicCount > 1) {
      throw new Error(`Only one signature of type "CIC" is allowed, found ${cicCount}`);
    }
    if (cosCount > 1) {
      throw new Error(`Only one signature of type "COS" is allowed, found ${cosCount}`);
    }
    pkt.raw = new TextEncoder().encode(jsonStr);
    return pkt;
  }

  /**
   * Creates a signed message (OSM - OpenPubkey Signed Message) using this PK Token
   *
   * OSMs are a type of JWS that commit to the PK Token which was used to generate them.
   * This provides proof-of-possession of the private key associated with the PK Token.
   *
   * @param content - The message content to sign
   * @param signer - The private key to sign with (must match the CIC public key)
   * @returns The signed message as a JWS compact serialization
   */
  async newSignedMessage(content: Uint8Array, signer: crypto.KeyObject): Promise<Uint8Array> {
    const { newSignedMessage } = await import('./osm.js');
    return newSignedMessage(this, content, signer);
  }

  /**
   * Creates a signed message (OSM) using this PK Token (Browser version)
   *
   * This is the browser-compatible version that works with Web Crypto API CryptoKey objects.
   * Use this instead of newSignedMessage() when working in browser environments.
   *
   * @param content - The message content to sign
   * @param signer - The browser CryptoKey to sign with (must match the CIC public key)
   * @returns The signed message as a JWS compact serialization
   */
  async newSignedMessageBrowser(content: Uint8Array, signer: CryptoKey): Promise<Uint8Array> {
    const { newSignedMessageBrowser } = await import('./osm-browser.js');
    return newSignedMessageBrowser(this, content, signer);
  }

  /**
   * Verifies an OSM (OpenPubkey Signed Message) using this PK Token's public key
   *
   * This verifies that the message was signed by the holder of the private key
   * corresponding to this PK Token's CIC public key.
   *
   * Note: This does NOT verify that the PK Token itself is valid.
   * The PK Token should always be verified first before calling this function.
   *
   * @param osm - The signed message to verify
   * @param options - Verification options (e.g., expected typ value)
   * @returns The verified message content (payload)
   */
  async verifySignedMessage(
    osm: Uint8Array,
    options?: { typ?: string }
  ): Promise<Uint8Array> {
    const { verifySignedMessage } = await import('./osm.js');
    return verifySignedMessage(this, osm, options);
  }

  /**
   * Verifies an OSM (OpenPubkey Signed Message) using this PK Token (Browser version)
   *
   * This is the browser-compatible version. Works identically to verifySignedMessage()
   * but is available for consistency with newSignedMessageBrowser().
   *
   * @param osm - The signed message to verify
   * @param options - Verification options (e.g., expected typ value)
   * @returns The verified message content (payload)
   */
  async verifySignedMessageBrowser(
    osm: Uint8Array,
    options?: { typ?: string }
  ): Promise<Uint8Array> {
    const { verifySignedMessageBrowser } = await import('./osm-browser.js');
    return verifySignedMessageBrowser(this, osm, options);
  }
}
