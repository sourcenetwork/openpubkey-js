import * as jose from 'jose';
import {
  gq256SignJWT,
  gq256VerifyJWT,
  new256SignerVerifier,
  originalJWTHeaders,
  GQ256,
} from '../gq.js';

describe('GQ Signatures', () => {
  let rsaKeyPair: jose.GenerateKeyPairResult<jose.KeyLike>;
  let rsaPublicJwk: jose.JWK;

  beforeAll(async () => {
    // Generate RSA key pair for testing
    rsaKeyPair = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
    rsaPublicJwk = await jose.exportJWK(rsaKeyPair.publicKey);
  });

  describe('gq256SignJWT', () => {
    it('should sign a JWT with GQ256', async () => {
      // Create a signed JWT
      const jwt = await new jose.SignJWT({ sub: 'user123' })
        .setProtectedHeader({ alg: 'RS256' })
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(rsaKeyPair.privateKey);

      const jwtBytes = new TextEncoder().encode(jwt);
      const gqJwt = await gq256SignJWT(rsaPublicJwk, jwtBytes);

      expect(gqJwt).toBeInstanceOf(Uint8Array);
      const gqJwtStr = new TextDecoder().decode(gqJwt);
      expect(gqJwtStr.split('.').length).toBe(3);

      // Verify the header has GQ256 algorithm
      const parts = gqJwtStr.split('.');
      const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
      expect(header.alg).toBe(GQ256);
    });

    it('should reject JWT with wrong public key', async () => {
      // Create a different key pair
      const otherKeyPair = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const otherPublicJwk = await jose.exportJWK(otherKeyPair.publicKey);

      const jwt = await new jose.SignJWT({ sub: 'user123' })
        .setProtectedHeader({ alg: 'RS256' })
        .sign(rsaKeyPair.privateKey);

      const jwtBytes = new TextEncoder().encode(jwt);

      await expect(gq256SignJWT(otherPublicJwk, jwtBytes)).rejects.toThrow(
        'Incorrect public key supplied'
      );
    });
  });

  describe('gq256VerifyJWT', () => {
    it('should verify a GQ-signed JWT', async () => {
      const jwt = await new jose.SignJWT({ sub: 'user123' })
        .setProtectedHeader({ alg: 'RS256' })
        .setIssuedAt()
        .sign(rsaKeyPair.privateKey);

      const jwtBytes = new TextEncoder().encode(jwt);
      const gqJwt = await gq256SignJWT(rsaPublicJwk, jwtBytes);

      const isValid = await gq256VerifyJWT(rsaPublicJwk, gqJwt);
      expect(isValid).toBe(true);
    });

    it('should reject tampered GQ-signed JWT', async () => {
      const jwt = await new jose.SignJWT({ sub: 'user123' })
        .setProtectedHeader({ alg: 'RS256' })
        .sign(rsaKeyPair.privateKey);

      const jwtBytes = new TextEncoder().encode(jwt);
      const gqJwt = await gq256SignJWT(rsaPublicJwk, jwtBytes);

      // Tamper with the payload
      const gqJwtStr = new TextDecoder().decode(gqJwt);
      const parts = gqJwtStr.split('.');
      parts[1] = parts[1] + 'tampered';
      const tamperedJwt = new TextEncoder().encode(parts.join('.'));

      const isValid = await gq256VerifyJWT(rsaPublicJwk, tamperedJwt);
      expect(isValid).toBe(false);
    });

    it('should reject GQ JWT verified with wrong key', async () => {
      const jwt = await new jose.SignJWT({ sub: 'user123' })
        .setProtectedHeader({ alg: 'RS256' })
        .sign(rsaKeyPair.privateKey);

      const jwtBytes = new TextEncoder().encode(jwt);
      const gqJwt = await gq256SignJWT(rsaPublicJwk, jwtBytes);

      // Try to verify with a different key
      const otherKeyPair = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const otherPublicJwk = await jose.exportJWK(otherKeyPair.publicKey);

      const isValid = await gq256VerifyJWT(otherPublicJwk, gqJwt);
      expect(isValid).toBe(false);
    });
  });

  describe('new256SignerVerifier', () => {
    it('should create a signer/verifier from RSA public key', async () => {
      const sv = await new256SignerVerifier(rsaPublicJwk);
      expect(sv).toBeDefined();
      expect(sv.sign).toBeDefined();
      expect(sv.verify).toBeDefined();
      expect(sv.signJWT).toBeDefined();
      expect(sv.verifyJWT).toBeDefined();
    });

    it('should reject non-65537 exponent', async () => {
      const invalidJwk = { ...rsaPublicJwk, e: 'Aw' }; // e=3
      await expect(new256SignerVerifier(invalidJwk)).rejects.toThrow(
        'Only RSA exponent 65537 is currently supported'
      );
    });
  });

  describe('originalJWTHeaders', () => {
    it('should extract original headers from GQ JWT', async () => {
      const jwt = await new jose.SignJWT({ sub: 'user123' })
        .setProtectedHeader({ alg: 'RS256', kid: 'key-1' })
        .sign(rsaKeyPair.privateKey);

      const jwtBytes = new TextEncoder().encode(jwt);
      const gqJwt = await gq256SignJWT(rsaPublicJwk, jwtBytes);

      const origHeaders = originalJWTHeaders(gqJwt);
      expect(origHeaders).toBeInstanceOf(Uint8Array);

      // The original headers should be the first segment of the original JWT
      const originalFirstSegment = jwt.split('.')[0];
      expect(new TextDecoder().decode(origHeaders)).toBe(originalFirstSegment);
    });

    it('should throw for non-GQ JWT', () => {
      const regularJwt = new TextEncoder().encode('eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig');
      expect(() => originalJWTHeaders(regularJwt)).toThrow('Expected GQ256 alg');
    });
  });
});
