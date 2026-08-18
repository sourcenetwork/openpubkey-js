import * as jose from 'jose';
import {
  DefaultProviderVerifier,
  newProviderVerifier,
  type ProviderVerifierOpts,
} from '../provider-verifier.js';
import { CommitTypes } from '../types.js';
import { Claims } from '../../pktoken/clientinstance/claims.js';
import { PublicKeyFinder } from '../../discover/discover.js';

describe('DefaultProviderVerifier', () => {
  const testIssuer = 'https://accounts.example.com';
  let keyPair: jose.GenerateKeyPairResult<jose.KeyLike>;
  let publicJwk: jose.JWK;

  beforeAll(async () => {
    keyPair = await jose.generateKeyPair('RS256');
    publicJwk = await jose.exportJWK(keyPair.publicKey);
    publicJwk.kid = 'test-key-1';
    publicJwk.alg = 'RS256';
  });

  // Mock public key finder that returns our test key
  const createMockPublicKeyFinder = (): PublicKeyFinder => {
    const finder = new PublicKeyFinder(async () => {
      return JSON.stringify({
        keys: [publicJwk],
      });
    });
    return finder;
  };

  const createTestToken = async (
    payload: Record<string, unknown>,
    kid: string = 'test-key-1'
  ): Promise<string> => {
    return await new jose.SignJWT(payload as jose.JWTPayload)
      .setProtectedHeader({ alg: 'RS256', kid })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(keyPair.privateKey);
  };

  describe('constructor', () => {
    it('should create a verifier with the provided issuer and options', () => {
      const opts: ProviderVerifierOpts = {
        commitType: CommitTypes.NONCE_CLAIM,
      };

      const verifier = new DefaultProviderVerifier(testIssuer, opts);
      expect(verifier.issuer()).toBe(testIssuer);
    });
  });

  describe('issuer', () => {
    it('should return the issuer', () => {
      const verifier = newProviderVerifier(testIssuer, {
        commitType: CommitTypes.NONCE_CLAIM,
      });

      expect(verifier.issuer()).toBe(testIssuer);
    });
  });

  describe('verifyIDToken', () => {
    it('should verify a valid ID token with nonce commitment', async () => {
      const cicHash = 'test-cic-hash-value';

      // Create CIC mock
      const cicMock = {
        hash: async () => new TextEncoder().encode(cicHash),
      } as Claims;

      const token = await createTestToken({
        iss: testIssuer,
        sub: 'user123',
        aud: 'client-id',
        nonce: cicHash,
      });

      const verifier = newProviderVerifier(testIssuer, {
        commitType: CommitTypes.NONCE_CLAIM,
        clientID: 'client-id',
        discoverPublicKey: createMockPublicKeyFinder(),
      });

      await expect(
        verifier.verifyIDToken(new TextEncoder().encode(token), cicMock)
      ).resolves.toBeUndefined();
    });

    it('should throw for missing nonce', async () => {
      const cicHash = 'test-cic-hash-value';
      const cicMock = {
        hash: async () => new TextEncoder().encode(cicHash),
      } as Claims;

      const token = await createTestToken({
        iss: testIssuer,
        sub: 'user123',
        aud: 'client-id',
        // nonce is missing
      });

      const verifier = newProviderVerifier(testIssuer, {
        commitType: CommitTypes.NONCE_CLAIM,
        clientID: 'client-id',
        discoverPublicKey: createMockPublicKeyFinder(),
      });

      await expect(
        verifier.verifyIDToken(new TextEncoder().encode(token), cicMock)
      ).rejects.toThrow('Missing nonce');
    });

    it('should throw for nonce mismatch', async () => {
      const cicMock = {
        hash: async () => new TextEncoder().encode('expected-hash'),
      } as Claims;

      const token = await createTestToken({
        iss: testIssuer,
        sub: 'user123',
        aud: 'client-id',
        nonce: 'wrong-hash',
      });

      const verifier = newProviderVerifier(testIssuer, {
        commitType: CommitTypes.NONCE_CLAIM,
        clientID: 'client-id',
        discoverPublicKey: createMockPublicKeyFinder(),
      });

      await expect(
        verifier.verifyIDToken(new TextEncoder().encode(token), cicMock)
      ).rejects.toThrow('Nonce mismatch');
    });

    it('should throw for audience mismatch', async () => {
      const cicMock = {
        hash: async () => new TextEncoder().encode('hash'),
      } as Claims;

      const token = await createTestToken({
        iss: testIssuer,
        sub: 'user123',
        aud: 'wrong-client',
        nonce: 'hash',
      });

      const verifier = newProviderVerifier(testIssuer, {
        commitType: CommitTypes.NONCE_CLAIM,
        clientID: 'expected-client',
        discoverPublicKey: createMockPublicKeyFinder(),
      });

      await expect(
        verifier.verifyIDToken(new TextEncoder().encode(token), cicMock)
      ).rejects.toThrow('Audience mismatch');
    });

    it('should validate the authorized party for multiple audiences', async () => {
      const cicMock = {
        hash: async () => new TextEncoder().encode('hash'),
      } as Claims;
      const token = await createTestToken({
        iss: testIssuer,
        sub: 'user123',
        aud: ['client-id', 'another-audience'],
        azp: 'another-client',
        nonce: 'hash',
      });
      const verifier = newProviderVerifier(testIssuer, {
        commitType: CommitTypes.NONCE_CLAIM,
        clientID: 'client-id',
        discoverPublicKey: createMockPublicKeyFinder(),
      });

      await expect(
        verifier.verifyIDToken(new TextEncoder().encode(token), cicMock)
      ).rejects.toThrow('Authorized party mismatch');

      const missingAzp = await createTestToken({
        iss: testIssuer,
        sub: 'user123',
        aud: ['client-id', 'another-audience'],
        nonce: 'hash',
      });
      await expect(
        verifier.verifyIDToken(new TextEncoder().encode(missingAzp), cicMock)
      ).rejects.toThrow('Missing authorized party');
    });

    it('should skip client ID check when skipClientIDCheck is true', async () => {
      const cicHash = 'hash';
      const cicMock = {
        hash: async () => new TextEncoder().encode(cicHash),
      } as Claims;

      const token = await createTestToken({
        iss: testIssuer,
        sub: 'user123',
        aud: 'any-client',
        nonce: cicHash,
      });

      const verifier = newProviderVerifier(testIssuer, {
        commitType: CommitTypes.NONCE_CLAIM,
        clientID: 'different-client',
        skipClientIDCheck: true,
        discoverPublicKey: createMockPublicKeyFinder(),
      });

      await expect(
        verifier.verifyIDToken(new TextEncoder().encode(token), cicMock)
      ).resolves.toBeUndefined();
    });

    it('should throw for GQ only mode', async () => {
      const cicMock = {
        hash: async () => new TextEncoder().encode('hash'),
      } as Claims;

      const token = await createTestToken({
        iss: testIssuer,
        sub: 'user123',
        aud: 'client-id',
      });

      const verifier = newProviderVerifier(testIssuer, {
        commitType: CommitTypes.GQ_BOUND,
        gqOnly: true,
        discoverPublicKey: createMockPublicKeyFinder(),
      });

      await expect(
        verifier.verifyIDToken(new TextEncoder().encode(token), cicMock)
      ).rejects.toThrow('GQ signatures are not supported');
    });

    it('should verify aud commitment when using AUD_CLAIM', async () => {
      const cicHash = 'cic-hash-in-aud';
      const cicMock = {
        hash: async () => new TextEncoder().encode(cicHash),
      } as Claims;

      const token = await createTestToken({
        iss: testIssuer,
        sub: 'user123',
        aud: [cicHash, 'client-id'],
      });

      const verifier = newProviderVerifier(testIssuer, {
        commitType: CommitTypes.AUD_CLAIM,
        skipClientIDCheck: true,
        discoverPublicKey: createMockPublicKeyFinder(),
      });

      await expect(
        verifier.verifyIDToken(new TextEncoder().encode(token), cicMock)
      ).resolves.toBeUndefined();
    });
  });

  describe('publicKeyByToken', () => {
    it('should return the public key for a token', async () => {
      const token = await createTestToken({
        iss: testIssuer,
        sub: 'user123',
      });

      const verifier = newProviderVerifier(testIssuer, {
        commitType: CommitTypes.NONCE_CLAIM,
        discoverPublicKey: createMockPublicKeyFinder(),
      });

      const jwk = await verifier.publicKeyByToken(new TextEncoder().encode(token));
      expect(jwk.kid).toBe('test-key-1');
      expect(jwk.kty).toBe('RSA');
    });
  });

  describe('verifyRefreshedIDToken', () => {
    it('should verify a refreshed token with matching claims', async () => {
      const origToken = await createTestToken({
        iss: testIssuer,
        sub: 'user123',
        aud: 'client-id',
      });

      const refreshedToken = await createTestToken({
        iss: testIssuer,
        sub: 'user123',
        aud: 'client-id',
      });

      const verifier = newProviderVerifier(testIssuer, {
        commitType: CommitTypes.NONCE_CLAIM,
        discoverPublicKey: createMockPublicKeyFinder(),
      });

      await expect(
        verifier.verifyRefreshedIDToken(
          new TextEncoder().encode(origToken),
          new TextEncoder().encode(refreshedToken)
        )
      ).resolves.toBeUndefined();
    });

    it('should throw for subject mismatch', async () => {
      const origToken = await createTestToken({
        iss: testIssuer,
        sub: 'user123',
        aud: 'client-id',
      });

      const refreshedToken = await createTestToken({
        iss: testIssuer,
        sub: 'different-user',
        aud: 'client-id',
      });

      const verifier = newProviderVerifier(testIssuer, {
        commitType: CommitTypes.NONCE_CLAIM,
        discoverPublicKey: createMockPublicKeyFinder(),
      });

      await expect(
        verifier.verifyRefreshedIDToken(
          new TextEncoder().encode(origToken),
          new TextEncoder().encode(refreshedToken)
        )
      ).rejects.toThrow('Subject mismatch');
    });

    it('should throw for issuer mismatch', async () => {
      const origToken = await createTestToken({
        iss: testIssuer,
        sub: 'user123',
        aud: 'client-id',
      });

      const refreshedToken = await createTestToken({
        iss: 'https://different-issuer.com',
        sub: 'user123',
        aud: 'client-id',
      });

      const verifier = newProviderVerifier(testIssuer, {
        commitType: CommitTypes.NONCE_CLAIM,
        discoverPublicKey: createMockPublicKeyFinder(),
      });

      await expect(
        verifier.verifyRefreshedIDToken(
          new TextEncoder().encode(origToken),
          new TextEncoder().encode(refreshedToken)
        )
      ).rejects.toThrow('Issuer mismatch');
    });
  });

  describe('newProviderVerifier', () => {
    it('should create a DefaultProviderVerifier', () => {
      const verifier = newProviderVerifier(testIssuer, {
        commitType: CommitTypes.NONCE_CLAIM,
      });

      expect(verifier).toBeInstanceOf(DefaultProviderVerifier);
      expect(verifier.issuer()).toBe(testIssuer);
    });
  });
});
