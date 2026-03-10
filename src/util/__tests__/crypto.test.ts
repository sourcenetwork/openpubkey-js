import {
  b64SHA3_256,
  genKeyPair,
  randomBytes,
  randomHex,
  isBrowserEnvironment,
  KeyAlgorithm,
} from '../crypto.js';
import * as crypto from 'crypto';

describe('Crypto Utils', () => {
  describe('b64SHA3_256', () => {
    it('should hash and base64url encode', async () => {
      const input = new TextEncoder().encode('hello');
      const result = await b64SHA3_256(input);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBeGreaterThan(0);
    });

    it('should produce consistent results', async () => {
      const input = new TextEncoder().encode('test');
      const result1 = await b64SHA3_256(input);
      const result2 = await b64SHA3_256(input);
      expect(result1).toEqual(result2);
    });

    it('should produce different results for different inputs', async () => {
      const result1 = await b64SHA3_256(new TextEncoder().encode('hello'));
      const result2 = await b64SHA3_256(new TextEncoder().encode('world'));
      expect(result1).not.toEqual(result2);
    });
  });

  describe('genKeyPair', () => {
    it('should generate ES256 key pair', async () => {
      const key = await genKeyPair(KeyAlgorithm.ES256);
      expect(key).toBeDefined();
      // In Node.js, verify it's a KeyObject
      const keyObj = key as crypto.KeyObject;
      expect(keyObj.type).toBe('private');
      expect(keyObj.asymmetricKeyType).toBe('ec');
    });

    it('should generate RS256 key pair', async () => {
      const key = await genKeyPair(KeyAlgorithm.RS256);
      expect(key).toBeDefined();
      const keyObj = key as crypto.KeyObject;
      expect(keyObj.type).toBe('private');
      expect(keyObj.asymmetricKeyType).toBe('rsa');
    });

    it('should generate EdDSA key pair', async () => {
      const key = await genKeyPair(KeyAlgorithm.EdDSA);
      expect(key).toBeDefined();
      const keyObj = key as crypto.KeyObject;
      expect(keyObj.type).toBe('private');
      expect(keyObj.asymmetricKeyType).toBe('ed25519');
    });
  });

  describe('randomBytes', () => {
    it('should generate bytes of specified size', () => {
      const bytes = randomBytes(16);
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBe(16);
    });

    it('should generate different bytes each time', () => {
      const bytes1 = randomBytes(16);
      const bytes2 = randomBytes(16);
      expect(bytes1).not.toEqual(bytes2);
    });

    it('should handle zero size', () => {
      const bytes = randomBytes(0);
      expect(bytes.length).toBe(0);
    });
  });

  describe('randomHex', () => {
    it('should generate hex string of correct length', () => {
      const hex = randomHex(16);
      expect(hex.length).toBe(32); // 16 bytes = 32 hex chars
      expect(/^[0-9a-f]+$/.test(hex)).toBe(true);
    });

    it('should generate different values each time', () => {
      const hex1 = randomHex(16);
      const hex2 = randomHex(16);
      expect(hex1).not.toBe(hex2);
    });
  });

  describe('isBrowserEnvironment', () => {
    it('should return false in Node.js', () => {
      expect(isBrowserEnvironment()).toBe(false);
    });
  });
});
