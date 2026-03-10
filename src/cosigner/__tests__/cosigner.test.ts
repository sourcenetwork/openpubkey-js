import * as crypto from 'crypto';
import { Cosigner } from '../cosigner.js';
import { KeyAlgorithm } from '../../util/crypto.js';
import { PKToken } from '../../pktoken/pktoken.js';
import type { CosignerClaims } from '../../pktoken/cos.js';

describe('Cosigner', () => {
  let keyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject };

  beforeAll(() => {
    keyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
  });

  describe('constructor', () => {
    it('should create a Cosigner with the provided key and algorithm', () => {
      const cosigner = new Cosigner(keyPair.privateKey, KeyAlgorithm.ES256);
      expect(cosigner).toBeInstanceOf(Cosigner);
    });
  });

  describe('getAlgorithm', () => {
    it('should return the algorithm', () => {
      const cosigner = new Cosigner(keyPair.privateKey, KeyAlgorithm.ES256);
      expect(cosigner.getAlgorithm()).toBe(KeyAlgorithm.ES256);
    });

    it('should return RS256 when constructed with RS256', () => {
      const rsaKeyPair = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
      });
      const cosigner = new Cosigner(rsaKeyPair.privateKey, KeyAlgorithm.RS256);
      expect(cosigner.getAlgorithm()).toBe(KeyAlgorithm.RS256);
    });
  });

  describe('cosign', () => {
    it('should cosign a PKToken with claims', async () => {
      const cosigner = new Cosigner(keyPair.privateKey, KeyAlgorithm.ES256);

      // Create a mock PKToken with payload
      const pkt = new PKToken();
      const payload = JSON.stringify({
        sub: 'user123',
        iss: 'https://example.com',
        aud: 'client-id',
      });
      pkt.payload = new TextEncoder().encode(payload);

      const cosClaims: CosignerClaims = {
        iss: 'https://cosigner.example.com',
        kid: 'key-1',
        alg: 'ES256',
        eid: 'event-123',
        auth_time: Math.floor(Date.now() / 1000),
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        ruri: 'https://app.example.com/callback',
        nonce: 'nonce-abc123',
      };

      const signature = await cosigner.cosign(pkt, cosClaims);

      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBeGreaterThan(0);
    });

    it('should include typ in headers when provided', async () => {
      const cosigner = new Cosigner(keyPair.privateKey, KeyAlgorithm.ES256);

      const pkt = new PKToken();
      pkt.payload = new TextEncoder().encode(JSON.stringify({ sub: 'user' }));

      const cosClaims: CosignerClaims = {
        iss: 'https://cosigner.example.com',
        kid: 'key-1',
        alg: 'ES256',
        eid: 'event-123',
        auth_time: Math.floor(Date.now() / 1000),
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        ruri: 'https://app.example.com/callback',
        nonce: 'nonce-abc123',
        typ: 'cos',
      };

      const signature = await cosigner.cosign(pkt, cosClaims);
      expect(signature).toBeInstanceOf(Uint8Array);
    });

    it('should default typ to "cos" when not provided', async () => {
      const cosigner = new Cosigner(keyPair.privateKey, KeyAlgorithm.ES256);

      const pkt = new PKToken();
      pkt.payload = new TextEncoder().encode(JSON.stringify({ sub: 'user' }));

      const cosClaims: CosignerClaims = {
        iss: 'https://cosigner.example.com',
        kid: 'key-1',
        alg: 'ES256',
        eid: 'event-123',
        auth_time: Math.floor(Date.now() / 1000),
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        ruri: 'https://app.example.com/callback',
        nonce: 'nonce-abc123',
      };

      const signature = await cosigner.cosign(pkt, cosClaims);
      expect(signature).toBeInstanceOf(Uint8Array);
    });
  });
});
