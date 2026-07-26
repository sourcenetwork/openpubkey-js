/**
 * Crypto adapter that works in both Node.js and browser environments
 */

import { base64EncodeForJWT } from './base64.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import * as nodeCryptoModule from 'crypto';

// Browser type declarations
declare const window: { crypto?: Crypto } | undefined;

// Detect environment
const isBrowser = typeof window !== 'undefined' && typeof window.crypto !== 'undefined';

/**
 * Computes SHA3-256 hash and returns base64url encoded result as bytes
 */
export async function b64SHA3_256(msg: Uint8Array): Promise<Uint8Array> {
  const hash = sha3_256(msg);
  return base64EncodeForJWT(hash);
}

/**
 * Supported key algorithms
 */
export enum KeyAlgorithm {
  ES256 = 'ES256',
  RS256 = 'RS256',
  EdDSA = 'EdDSA',
}

export interface WebCryptoAlgorithm {
  importParams: EcKeyImportParams | RsaHashedImportParams;
  generateParams: EcKeyGenParams | RsaHashedKeyGenParams;
  signParams: AlgorithmIdentifier | EcdsaParams;
}

export function webCryptoAlgorithm(algorithm: string): WebCryptoAlgorithm {
  switch (algorithm) {
    case KeyAlgorithm.ES256: {
      const keyParams: EcKeyImportParams = { name: 'ECDSA', namedCurve: 'P-256' };
      return {
        importParams: keyParams,
        generateParams: keyParams,
        signParams: { name: 'ECDSA', hash: 'SHA-256' },
      };
    }
    case KeyAlgorithm.RS256: {
      const importParams: RsaHashedImportParams = {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256',
      };
      return {
        importParams,
        generateParams: {
          ...importParams,
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
        },
        signParams: { name: 'RSASSA-PKCS1-v1_5' },
      };
    }
    default:
      throw new Error(`Unsupported Web Crypto algorithm: ${algorithm}`);
  }
}

/**
 * Generates a key pair for the specified algorithm.
 * Returns CryptoKey in browser, KeyObject in Node.js.
 */
export async function genKeyPair(
  alg: KeyAlgorithm
): Promise<CryptoKey | nodeCryptoModule.KeyObject> {
  if (isBrowser) {
    return genKeyPairBrowser(alg);
  } else {
    return genKeyPairNode(alg);
  }
}

/**
 * Browser implementation using Web Crypto API
 */
async function genKeyPairBrowser(alg: KeyAlgorithm): Promise<CryptoKey> {
  if (alg === KeyAlgorithm.EdDSA) {
    throw new Error('EdDSA not yet supported in browser');
  }
  const keyPair = (await crypto.subtle.generateKey(webCryptoAlgorithm(alg).generateParams, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  return keyPair.privateKey;
}

/**
 * Node.js implementation using crypto module
 */
function genKeyPairNode(alg: KeyAlgorithm): Promise<nodeCryptoModule.KeyObject> {
  return new Promise((resolve, reject) => {
    switch (alg) {
      case KeyAlgorithm.ES256:
        nodeCryptoModule.generateKeyPair(
          'ec',
          { namedCurve: 'P-256' },
          (err, _publicKey, privateKey) => {
            if (err) reject(err);
            else resolve(privateKey);
          }
        );
        break;
      case KeyAlgorithm.RS256:
        nodeCryptoModule.generateKeyPair(
          'rsa',
          { modulusLength: 2048 },
          (err, _publicKey, privateKey) => {
            if (err) reject(err);
            else resolve(privateKey);
          }
        );
        break;
      case KeyAlgorithm.EdDSA:
        nodeCryptoModule.generateKeyPair('ed25519', {}, (err, _publicKey, privateKey) => {
          if (err) reject(err);
          else resolve(privateKey);
        });
        break;
      default:
        reject(new Error(`Unsupported algorithm: ${alg}`));
    }
  });
}

/**
 * Generates random bytes.
 * Works in both Node.js and browser.
 */
export function randomBytes(size: number): Uint8Array {
  if (isBrowser) {
    return crypto.getRandomValues(new Uint8Array(size));
  } else {
    return new Uint8Array(nodeCryptoModule.randomBytes(size));
  }
}

/**
 * Generates a random hex string
 */
export function randomHex(size: number): string {
  const bytes = randomBytes(size);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Check if running in browser environment
 */
export function isBrowserEnvironment(): boolean {
  return isBrowser;
}
