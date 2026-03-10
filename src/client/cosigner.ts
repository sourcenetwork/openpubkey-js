import * as crypto from 'crypto';
import * as http from 'http';
import * as jose from 'jose';
import type { PKToken } from '../pktoken/pktoken.js';
import { SignatureType } from '../pktoken/pktoken.js';
import type { InitMFAAuth } from '../cosigner/msgs.js';
import { base64EncodeForJWT, base64DecodeForJWT } from '../util/base64.js';

/**
 * Cosigner Provider for MFA authentication
 */
export class CosignerProvider {
  issuer: string;
  callbackPath: string;

  constructor(issuer: string, callbackPath: string) {
    this.issuer = issuer;
    this.callbackPath = callbackPath;
  }

  /**
   * Requests a cosigned token from the MFA cosigner
   *
   * @param signer - The private key for signing
   * @param pkt - The PK Token to cosign
   * @param onRedirect - Callback that receives the redirect URI for the browser
   * @returns The cosigned PK Token
   */
  async requestToken(
    signer: crypto.KeyObject,
    pkt: PKToken,
    onRedirect: (uri: string) => void
  ): Promise<PKToken> {
    // Find an available port
    const port = await this.findAvailablePort();
    const host = `localhost:${port}`;
    const redirectURI = `http://${host}${this.callbackPath}`;
    // Create channels for communication
    const result: {
      signature?: Uint8Array;
      error?: Error;
    } = {};
    // Create HTTP server for callback
    const server = http.createServer(async (req, res) => {
      try {
        const url = new URL(req.url || '', `http://${host}`);
        if (url.pathname !== this.callbackPath) {
          res.writeHead(404);
          res.end('Not found');
          return;
        }
        // Get authcode from cosigner
        const authcode = url.searchParams.get('authcode');
        if (!authcode) {
          throw new Error('Cosigner did not return an authcode in the URI');
        }
        // Sign authcode from cosigner under PK Token
        const sig2 = await pkt.newSignedMessage(new TextEncoder().encode(authcode), signer);
        const authcodeSigUri = this.buildAuthcodeURI(sig2);
        // Request cosigner signature
        const response = await fetch(authcodeSigUri);
        if (!response.ok) {
          throw new Error(`Cosigner request failed: ${response.statusText}`);
        }
        const resBody = await response.arrayBuffer();
        const cosSig = base64DecodeForJWT(new Uint8Array(resBody));
        // Success
        result.signature = cosSig;
        res.writeHead(200);
        res.end('You may now close this window');
      } catch (error) {
        result.error = error as Error;
        res.writeHead(500);
        res.end((error as Error).message);
      }
    });
    // Start server
    await new Promise<void>((resolve, reject) => {
      server.listen(port, 'localhost', () => resolve());
      server.on('error', reject);
    });
    try {
      // Create init auth message
      const initAuthMsgJson = this.createInitAuthSig(redirectURI);
      const nonce = initAuthMsgJson.nonce;
      // Sign the init auth message
      const sig1 = await pkt.newSignedMessage(
        new TextEncoder().encode(JSON.stringify(initAuthMsgJson)),
        signer
      );
      // Serialize PK Token
      const pktJson = JSON.stringify(pkt);
      const pktBytes = new TextEncoder().encode(pktJson);
      // Build init auth URI
      const initAuthUri = this.buildInitAuthURI(pktBytes, sig1);
      // Trigger redirect
      onRedirect(initAuthUri);
      // Wait for result (with timeout)
      const timeoutMs = 5 * 60 * 1000; // 5 minutes
      const startTime = Date.now();
      while (!result.signature && !result.error) {
        if (Date.now() - startTime > timeoutMs) {
          throw new Error('Timeout waiting for cosigner response');
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      if (result.error) {
        throw result.error;
      }
      if (!result.signature) {
        throw new Error('No signature received from cosigner');
      }
      // Validate cosigner signature
      await this.validateCos(result.signature, nonce, redirectURI);
      // Add signature to PK Token
      await pkt.addSignature(result.signature, SignatureType.COS);
      return pkt;
    } finally {
      // Clean up server
      server.close();
    }
  }

  /**
   * Finds an available port
   */
  private async findAvailablePort(): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = http.createServer();
      server.listen(0, 'localhost', () => {
        const address = server.address();
        if (!address || typeof address === 'string') {
          reject(new Error('Failed to get port'));
          return;
        }
        const port = address.port;
        server.close(() => resolve(port));
      });
      server.on('error', reject);
    });
  }

  /**
   * Builds the init auth URI
   */
  private buildInitAuthURI(pktJson: Uint8Array, sig1: Uint8Array): string {
    const url = new URL(this.issuer);
    url.pathname = url.pathname.replace(/\/$/, '') + '/mfa-auth-init';
    url.searchParams.set('pkt', new TextDecoder().decode(base64EncodeForJWT(pktJson)));
    url.searchParams.set('sig1', new TextDecoder().decode(sig1));
    return url.toString();
  }

  /**
   * Builds the authcode URI
   */
  private buildAuthcodeURI(sig2: Uint8Array): string {
    const url = new URL(this.issuer);
    url.pathname = url.pathname.replace(/\/$/, '') + '/sign';
    url.searchParams.set('sig2', new TextDecoder().decode(sig2));
    return url.toString();
  }

  /**
   * Validates the cosigner signature
   */
  private async validateCos(
    cosSig: Uint8Array,
    expectedNonce: string,
    expectedRedirectURI: string
  ): Promise<void> {
    // Parse the JWS
    const cosSigStr = new TextDecoder().decode(cosSig);
    const parts = cosSigStr.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid cosigner signature format');
    }
    // Decode protected header
    const protectedHeader = JSON.parse(
      new TextDecoder().decode(jose.base64url.decode(parts[0]))
    );
    // Verify nonce
    if (!protectedHeader.nonce) {
      throw new Error('nonce not set in Cosigner signature protected header');
    }
    if (protectedHeader.nonce !== expectedNonce) {
      throw new Error('incorrect nonce set in Cosigner signature');
    }
    // Verify ruri (redirect URI)
    if (!protectedHeader.ruri) {
      throw new Error('ruri (redirect URI) not set in Cosigner signature protected header');
    }
    if (protectedHeader.ruri !== expectedRedirectURI) {
      throw new Error(
        `unexpected ruri (redirect URI) set in Cosigner signature, got ${protectedHeader.ruri} expected ${expectedRedirectURI}`
      );
    }
    // Verify issuer
    if (!protectedHeader.iss) {
      throw new Error('iss (Cosigner Issuer) not set in Cosigner signature protected header');
    }
    if (protectedHeader.iss !== this.issuer) {
      throw new Error(
        `unexpected iss (Cosigner Issuer) set in Cosigner signature, expected ${this.issuer}`
      );
    }
  }

  /**
   * Creates the init auth signature message
   */
  private createInitAuthSig(redirectURI: string): InitMFAAuth & { nonce: string } {
    // Generate random nonce (256 bits)
    const rBytes = crypto.randomBytes(32);
    const nonce = rBytes.toString('hex');
    // Validate redirect URI
    if (!redirectURI.endsWith(this.callbackPath)) {
      throw new Error(
        `redirectURI (${redirectURI}) does not end in expected callbackPath (${this.callbackPath})`
      );
    }
    const msg: InitMFAAuth = {
      iss: this.issuer,
      ruri: redirectURI,
      time: Math.floor(Date.now() / 1000),
      nonce: nonce,
    };
    return { ...msg, nonce };
  }
}
