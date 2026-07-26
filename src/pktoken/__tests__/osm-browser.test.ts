import { webcrypto } from 'node:crypto';
import * as jose from 'jose';
import type { PKToken } from '../pktoken.js';
import { newSignedMessageBrowser, verifySignedMessageBrowser } from '../osm-browser.js';

Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: webcrypto,
});

describe('browser signed messages', () => {
  it.each([
    ['ES256', { name: 'ECDSA', namedCurve: 'P-256' } as EcKeyGenParams],
    [
      'RS256',
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      } as RsaHashedKeyGenParams,
    ],
  ])('signs and verifies with a non-extractable %s key', async (algorithm, keyParams) => {
    const keyPair = (await crypto.subtle.generateKey(keyParams, false, [
      'sign',
      'verify',
    ])) as CryptoKeyPair;
    const publicKey = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    publicKey.alg = algorithm;
    const pkToken = {
      getCicValues: () => ({
        getPublicKey: () => publicKey,
      }),
      hash: async () => 'test-token-hash',
    } as unknown as PKToken;
    const content = new TextEncoder().encode('signed content');

    const signed = await newSignedMessageBrowser(pkToken, content, keyPair.privateKey);
    const verified = await verifySignedMessageBrowser(pkToken, signed);

    expect(verified).toEqual(content);
    expect(keyPair.privateKey.extractable).toBe(false);
    await expect(jose.exportJWK(keyPair.privateKey)).rejects.toThrow();
  });
});
