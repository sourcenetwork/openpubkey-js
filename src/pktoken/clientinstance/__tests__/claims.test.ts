import * as jose from 'jose';
import { Claims } from '../claims.js';

describe('Claims', () => {
  describe('parseClaims', () => {
    it('should parse valid claims', () => {
      const protectedClaims = {
        typ: 'CIC',
        alg: 'ES256',
        upk: { kty: 'EC', crv: 'P-256', x: 'test-x', y: 'test-y', alg: 'ES256' },
        rz: 'abc123random',
      };

      const claims = Claims.parseClaims(protectedClaims);
      expect(claims).toBeInstanceOf(Claims);
      expect(claims.getKeyAlgorithm()).toBe('ES256');
    });

    it('should preserve extra claims', () => {
      const protectedClaims = {
        typ: 'CIC',
        alg: 'ES256',
        upk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y', alg: 'ES256' },
        rz: 'random',
        custom: 'value',
        extra: 123,
      };

      const claims = Claims.parseClaims(protectedClaims);
      const protected_ = claims.getProtected();
      expect(protected_.custom).toBe('value');
      expect(protected_.extra).toBe(123);
    });

    it('should throw for missing rz claim', () => {
      expect(() =>
        Claims.parseClaims({
          alg: 'ES256',
          upk: { kty: 'EC', alg: 'ES256' },
        })
      ).toThrow('Missing required "rz" claim');
    });

    it('should throw for missing upk claim', () => {
      expect(() =>
        Claims.parseClaims({
          alg: 'ES256',
          rz: 'test',
        })
      ).toThrow('Missing required "upk" claim');
    });

    it('should throw for missing alg claim', () => {
      expect(() =>
        Claims.parseClaims({
          rz: 'test',
          upk: { kty: 'EC', alg: 'ES256' },
        })
      ).toThrow('Missing required "alg" claim');
    });

    it('should throw for mismatched alg', () => {
      expect(() =>
        Claims.parseClaims({
          alg: 'RS256',
          rz: 'test',
          upk: { kty: 'EC', alg: 'ES256' },
        })
      ).toThrow('different from algorithm');
    });
  });

  describe('getPublicKey', () => {
    it('should return the public key', () => {
      const upk = { kty: 'EC', crv: 'P-256', x: 'test-x', y: 'test-y', alg: 'ES256' };
      const claims = Claims.parseClaims({
        typ: 'CIC',
        alg: 'ES256',
        upk,
        rz: 'random',
      });

      expect(claims.getPublicKey()).toEqual(upk);
    });
  });

  describe('getKeyAlgorithm', () => {
    it('should return the algorithm', () => {
      const claims = Claims.parseClaims({
        typ: 'CIC',
        alg: 'ES256',
        upk: { kty: 'EC', alg: 'ES256' },
        rz: 'random',
      });

      expect(claims.getKeyAlgorithm()).toBe('ES256');
    });

    it('should return empty string when alg not set', () => {
      const claims = new Claims({ kty: 'EC' }, { rz: 'test', upk: { kty: 'EC' }, alg: 'ES256' });
      expect(claims.getKeyAlgorithm()).toBe('');
    });
  });

  describe('getProtected', () => {
    it('should return protected claims', () => {
      const protectedClaims = {
        typ: 'CIC',
        alg: 'ES256',
        upk: { kty: 'EC', alg: 'ES256' },
        rz: 'random',
        extra: 'data',
      };

      const claims = Claims.parseClaims(protectedClaims);
      const protected_ = claims.getProtected();

      expect(protected_.typ).toBe('CIC');
      expect(protected_.alg).toBe('ES256');
      expect(protected_.upk).toBeDefined();
      expect(protected_.rz).toBe('random');
      expect(protected_.extra).toBe('data');
    });
  });

  describe('hash', () => {
    it('should return consistent hash for same claims', async () => {
      const claims = Claims.parseClaims({
        typ: 'CIC',
        alg: 'ES256',
        upk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y', alg: 'ES256' },
        rz: 'fixed-random-value',
      });

      const hash1 = await claims.hash();
      const hash2 = await claims.hash();

      expect(hash1).toEqual(hash2);
    });

    it('should return different hashes for different claims', async () => {
      const claims1 = Claims.parseClaims({
        typ: 'CIC',
        alg: 'ES256',
        upk: { kty: 'EC', alg: 'ES256' },
        rz: 'random1',
      });
      const claims2 = Claims.parseClaims({
        typ: 'CIC',
        alg: 'ES256',
        upk: { kty: 'EC', alg: 'ES256' },
        rz: 'random2',
      });

      const hash1 = await claims1.hash();
      const hash2 = await claims2.hash();

      expect(hash1).not.toEqual(hash2);
    });

    it('should return base64url encoded hash', async () => {
      const claims = Claims.parseClaims({
        typ: 'CIC',
        alg: 'ES256',
        upk: { kty: 'EC', alg: 'ES256' },
        rz: 'random',
      });

      const hash = await claims.hash();

      expect(hash).toBeInstanceOf(Uint8Array);
      const hashStr = new TextDecoder().decode(hash);
      // Base64url should not contain +, /, or =
      expect(hashStr).not.toMatch(/[+/=]/);
    });
  });

  describe('sign', () => {
    it('should sign a token payload', async () => {
      const keyPair = await jose.generateKeyPair('ES256');

      const claims = Claims.parseClaims({
        typ: 'CIC',
        alg: 'ES256',
        upk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y', alg: 'ES256' },
        rz: 'random',
      });

      // Create a mock ID token
      const idToken = await new jose.SignJWT({ sub: 'user123', iss: 'https://example.com' })
        .setProtectedHeader({ alg: 'ES256' })
        .sign(keyPair.privateKey);

      const signed = await claims.sign(
        keyPair.privateKey,
        'ES256',
        new TextEncoder().encode(idToken)
      );

      expect(signed).toBeInstanceOf(Uint8Array);
      const signedStr = new TextDecoder().decode(signed);
      expect(signedStr.split('.').length).toBe(3);
    });

    it('should include CIC protected headers', async () => {
      const keyPair = await jose.generateKeyPair('ES256');

      const claims = Claims.parseClaims({
        typ: 'CIC',
        alg: 'ES256',
        upk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y', alg: 'ES256' },
        rz: 'random',
        custom: 'value',
      });

      const idToken = await new jose.SignJWT({ sub: 'user123' })
        .setProtectedHeader({ alg: 'ES256' })
        .sign(keyPair.privateKey);

      const signed = await claims.sign(
        keyPair.privateKey,
        'ES256',
        new TextEncoder().encode(idToken)
      );

      // Parse the signed token to verify headers
      const signedStr = new TextDecoder().decode(signed);
      const [headerB64] = signedStr.split('.');
      const headerJson = JSON.parse(atob(headerB64.replace(/-/g, '+').replace(/_/g, '/')));

      expect(headerJson.typ).toBe('CIC');
      expect(headerJson.custom).toBe('value');
      expect(headerJson.upk).toBeDefined();
    });

    it('should verify the signed CIC', async () => {
      const keyPair = await jose.generateKeyPair('ES256');
      const jwk = await jose.exportJWK(keyPair.publicKey);
      jwk.alg = 'ES256';

      const claims = Claims.parseClaims({
        typ: 'CIC',
        alg: 'ES256',
        upk: jwk,
        rz: 'random',
      });

      const idToken = await new jose.SignJWT({ sub: 'user123' })
        .setProtectedHeader({ alg: 'ES256' })
        .sign(keyPair.privateKey);

      const signed = await claims.sign(
        keyPair.privateKey,
        'ES256',
        new TextEncoder().encode(idToken)
      );

      // Verify the signature
      const signedStr = new TextDecoder().decode(signed);
      const result = await jose.jwtVerify(signedStr, keyPair.publicKey);
      expect(result.payload.sub).toBe('user123');
    });
  });

  describe('constructor', () => {
    it('should create claims with provided values', () => {
      const upk = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y', alg: 'ES256' };
      const protectedClaims = {
        typ: 'CIC',
        alg: 'ES256',
        upk,
        rz: 'test',
      };

      const claims = new Claims(upk, protectedClaims);

      expect(claims.getPublicKey()).toEqual(upk);
      expect(claims.getProtected()).toEqual(protectedClaims);
    });
  });
});
