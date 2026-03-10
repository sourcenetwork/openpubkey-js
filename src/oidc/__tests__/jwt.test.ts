import * as jose from 'jose';
import { Jwt } from '../jwt.js';

describe('Jwt', () => {
  let keyPair: jose.GenerateKeyPairResult<jose.KeyLike>;
  let publicJwk: jose.JWK;
  let signedJwt: string;

  beforeAll(async () => {
    keyPair = await jose.generateKeyPair('ES256');
    publicJwk = await jose.exportJWK(keyPair.publicKey);

    signedJwt = await new jose.SignJWT({
      sub: 'user123',
      iss: 'https://example.com',
      aud: 'client-id',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      email: 'user@example.com',
      nonce: 'test-nonce',
    })
      .setProtectedHeader({ alg: 'ES256', kid: 'key-1' })
      .sign(keyPair.privateKey);
  });

  describe('newJwt', () => {
    it('should parse a JWT token', () => {
      const jwt = Jwt.newJwt(new TextEncoder().encode(signedJwt));
      expect(jwt).toBeInstanceOf(Jwt);
    });

    it('should throw for invalid JWT format', () => {
      expect(() => Jwt.newJwt(new TextEncoder().encode('invalid'))).toThrow();
    });
  });

  describe('getProtectedHeader', () => {
    it('should return the protected header', () => {
      const jwt = Jwt.newJwt(new TextEncoder().encode(signedJwt));
      const header = jwt.getProtectedHeader();
      expect(header.alg).toBe('ES256');
      expect(header.kid).toBe('key-1');
    });
  });

  describe('getPayload', () => {
    it('should return the payload', () => {
      const jwt = Jwt.newJwt(new TextEncoder().encode(signedJwt));
      const payload = jwt.getPayload();
      expect(payload.sub).toBe('user123');
      expect(payload.iss).toBe('https://example.com');
      expect(payload.email).toBe('user@example.com');
    });
  });

  describe('getClaims', () => {
    it('should return OIDC claims', () => {
      const jwt = Jwt.newJwt(new TextEncoder().encode(signedJwt));
      const claims = jwt.getClaims();
      expect(claims.sub).toBe('user123');
      expect(claims.iss).toBe('https://example.com');
      expect(claims.aud).toBe('client-id');
      expect(claims.email).toBe('user@example.com');
      expect(claims.nonce).toBe('test-nonce');
    });

    it('should preserve audience as array when present', async () => {
      const jwtWithAudArray = await new jose.SignJWT({
        sub: 'user',
        iss: 'https://example.com',
        aud: ['client1', 'client2'],
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      })
        .setProtectedHeader({ alg: 'ES256' })
        .sign(keyPair.privateKey);

      const jwt = Jwt.newJwt(new TextEncoder().encode(jwtWithAudArray));
      const claims = jwt.getClaims();
      expect(Array.isArray(claims.aud)).toBe(true);
      expect(claims.aud).toEqual(['client1', 'client2']);
    });
  });

  describe('getSignature', () => {
    it('should return signature bytes', () => {
      const jwt = Jwt.newJwt(new TextEncoder().encode(signedJwt));
      const sig = jwt.getSignature();
      expect(sig).toBeInstanceOf(Uint8Array);
      expect(sig.length).toBeGreaterThan(0);
    });
  });

  describe('getAlgorithm', () => {
    it('should return the algorithm', () => {
      const jwt = Jwt.newJwt(new TextEncoder().encode(signedJwt));
      expect(jwt.getAlgorithm()).toBe('ES256');
    });
  });

  describe('getKeyId', () => {
    it('should return the key ID', () => {
      const jwt = Jwt.newJwt(new TextEncoder().encode(signedJwt));
      expect(jwt.getKeyId()).toBe('key-1');
    });

    it('should return undefined when no kid present', async () => {
      const jwtWithoutKid = await new jose.SignJWT({ sub: 'user' })
        .setProtectedHeader({ alg: 'ES256' })
        .sign(keyPair.privateKey);

      const jwt = Jwt.newJwt(new TextEncoder().encode(jwtWithoutKid));
      expect(jwt.getKeyId()).toBeUndefined();
    });
  });

  describe('getToken', () => {
    it('should return the original token bytes', () => {
      const tokenBytes = new TextEncoder().encode(signedJwt);
      const jwt = Jwt.newJwt(tokenBytes);
      expect(jwt.getToken()).toEqual(tokenBytes);
    });
  });

  describe('verify', () => {
    it('should verify a valid JWT signature', async () => {
      const jwt = Jwt.newJwt(new TextEncoder().encode(signedJwt));
      const isValid = await jwt.verify(publicJwk);
      expect(isValid).toBe(true);
    });

    it('should reject JWT with wrong key', async () => {
      const otherKeyPair = await jose.generateKeyPair('ES256');
      const otherPublicJwk = await jose.exportJWK(otherKeyPair.publicKey);

      const jwt = Jwt.newJwt(new TextEncoder().encode(signedJwt));
      const isValid = await jwt.verify(otherPublicJwk);
      expect(isValid).toBe(false);
    });

    it('should reject tampered JWT', async () => {
      // Create a JWT with different payload but same structure
      const tamperedJwt = await new jose.SignJWT({
        sub: 'attacker',
        iss: 'https://example.com',
        aud: 'client-id',
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
      })
        .setProtectedHeader({ alg: 'ES256', kid: 'key-1' })
        .sign(keyPair.privateKey);

      // Replace signature with original JWT's signature
      const originalParts = signedJwt.split('.');
      const tamperedParts = tamperedJwt.split('.');
      const mixedJwt = `${tamperedParts[0]}.${tamperedParts[1]}.${originalParts[2]}`;

      const jwt = Jwt.newJwt(new TextEncoder().encode(mixedJwt));
      const isValid = await jwt.verify(publicJwk);
      expect(isValid).toBe(false);
    });
  });
});
