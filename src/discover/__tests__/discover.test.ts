import * as jose from 'jose';
import { PublicKeyFinder, defaultPubkeyFinder } from '../discover.js';

describe('PublicKeyFinder', () => {
  let keyPair: jose.GenerateKeyPairResult<jose.KeyLike>;
  let publicJwk: jose.JWK;

  beforeAll(async () => {
    keyPair = await jose.generateKeyPair('RS256');
    publicJwk = await jose.exportJWK(keyPair.publicKey);
    publicJwk.kid = 'test-key-1';
    publicJwk.alg = 'RS256';
  });

  const createMockJwksFunc = (keys: jose.JWK[]) => {
    return async (_issuer: string) => {
      return JSON.stringify({ keys });
    };
  };

  describe('constructor', () => {
    it('should create a PublicKeyFinder with custom jwks function', () => {
      const finder = new PublicKeyFinder(createMockJwksFunc([publicJwk]));
      expect(finder).toBeInstanceOf(PublicKeyFinder);
    });

    it('should create a PublicKeyFinder with default jwks function', () => {
      const finder = new PublicKeyFinder();
      expect(finder).toBeInstanceOf(PublicKeyFinder);
    });
  });

  describe('byKeyID', () => {
    it('should find a key by kid', async () => {
      const finder = new PublicKeyFinder(createMockJwksFunc([publicJwk]));

      const record = await finder.byKeyID('https://example.com', 'test-key-1');

      expect(record.publicKey.kid).toBe('test-key-1');
      expect(record.alg).toBe('RS256');
      expect(record.issuer).toBe('https://example.com');
    });

    it('should throw for missing key', async () => {
      const finder = new PublicKeyFinder(createMockJwksFunc([publicJwk]));

      await expect(finder.byKeyID('https://example.com', 'non-existent')).rejects.toThrow(
        'Key with kid=non-existent not found'
      );
    });

    it('should default to RS256 when alg is not specified', async () => {
      const jwkWithoutAlg = { ...publicJwk };
      delete jwkWithoutAlg.alg;

      const finder = new PublicKeyFinder(createMockJwksFunc([jwkWithoutAlg]));

      const record = await finder.byKeyID('https://example.com', 'test-key-1');
      expect(record.alg).toBe('RS256');
    });

    it('should find correct key when multiple keys present', async () => {
      const secondKey = { ...publicJwk, kid: 'test-key-2', alg: 'ES256' };
      const finder = new PublicKeyFinder(createMockJwksFunc([publicJwk, secondKey]));

      const record = await finder.byKeyID('https://example.com', 'test-key-2');

      expect(record.publicKey.kid).toBe('test-key-2');
      expect(record.alg).toBe('ES256');
    });
  });

  describe('byToken', () => {
    it('should find a key by extracting kid from token', async () => {
      const token = await new jose.SignJWT({ sub: 'user' })
        .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
        .sign(keyPair.privateKey);

      const finder = new PublicKeyFinder(createMockJwksFunc([publicJwk]));

      const record = await finder.byToken('https://example.com', new TextEncoder().encode(token));

      expect(record.publicKey.kid).toBe('test-key-1');
    });

    it('should throw for token without kid', async () => {
      const token = await new jose.SignJWT({ sub: 'user' })
        .setProtectedHeader({ alg: 'RS256' }) // no kid
        .sign(keyPair.privateKey);

      const finder = new PublicKeyFinder(createMockJwksFunc([publicJwk]));

      await expect(
        finder.byToken('https://example.com', new TextEncoder().encode(token))
      ).rejects.toThrow('Token does not contain a kid');
    });
  });

  describe('defaultPubkeyFinder', () => {
    it('should create a default PublicKeyFinder', () => {
      const finder = defaultPubkeyFinder();
      expect(finder).toBeInstanceOf(PublicKeyFinder);
    });
  });
});
