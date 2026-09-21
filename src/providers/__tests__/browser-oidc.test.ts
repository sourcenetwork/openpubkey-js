import { webcrypto } from 'node:crypto';
import { jest } from '@jest/globals';
import * as jose from 'jose';
import type { Claims } from '../../pktoken/clientinstance/claims.js';
import { base64UrlEncode } from '../../util/base64.js';
import { BrowserOidcOp } from '../browser-oidc.js';

const issuer = 'https://tenant.auth0.com/';
const clientID = 'client-123';
const redirectURI = 'https://app.example.com/callback';
const transactionKey = 'opk_oidc_transaction';

class MemoryStorage implements Storage {
  private readonly values = new Map<string, string>();

  get length(): number {
    return this.values.size;
  }

  clear(): void {
    this.values.clear();
  }

  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  key(index: number): string | null {
    return [...this.values.keys()][index] ?? null;
  }

  removeItem(key: string): void {
    this.values.delete(key);
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value);
  }
}

const location = {
  href: redirectURI,
  assign: jest.fn<(url: string) => void>(),
};

Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto });
Object.defineProperty(globalThis, 'sessionStorage', {
  configurable: true,
  value: new MemoryStorage(),
});
Object.defineProperty(globalThis, 'window', {
  configurable: true,
  value: { crypto: webcrypto, location },
});

function discoveryResponse(overrides: Record<string, unknown> = {}): Response {
  return Response.json({
    issuer,
    authorization_endpoint: `${issuer}authorize`,
    token_endpoint: `${issuer}oauth/token`,
    jwks_uri: `${issuer}.well-known/jwks.json`,
    ...overrides,
  });
}

function mockClaims(): Claims {
  return {
    hash: async () => new TextEncoder().encode('cic-commitment'),
  } as Claims;
}

function testIDToken(nonce = 'cic-commitment'): string {
  const now = Math.floor(Date.now() / 1000);
  const encode = (value: object) =>
    base64UrlEncode(new TextEncoder().encode(JSON.stringify(value)));
  return `${encode({ alg: 'RS256', kid: 'provider-key' })}.${encode({
    iss: issuer,
    sub: 'auth0|user-1',
    aud: clientID,
    iat: now,
    exp: now + 300,
    nonce,
  })}.c2lnYXR1cmU`;
}

describe('BrowserOidcOp', () => {
  beforeEach(() => {
    sessionStorage.clear();
    location.href = redirectURI;
    location.assign.mockReset();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('starts authorization code flow with nonce binding and S256 PKCE', async () => {
    jest
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(
        discoveryResponse({ authorization_endpoint: `${issuer}authorize?connection=github` })
      );
    const op = new BrowserOidcOp({
      issuer,
      clientID,
      redirectURI,
      authorizationParams: { audience: 'https://trust.example.com', prompt: 'login' },
    });

    await expect(op.requestTokens(mockClaims())).rejects.toThrow('Redirecting to OAuth provider');
    expect(location.assign).toHaveBeenCalledTimes(1);
    const authorizationURL = new URL(location.assign.mock.calls[0][0]);
    const transaction = JSON.parse(sessionStorage.getItem(transactionKey)!);
    const digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(transaction.codeVerifier)
    );

    expect(authorizationURL.origin + authorizationURL.pathname).toBe(`${issuer}authorize`);
    expect(authorizationURL.searchParams.get('response_type')).toBe('code');
    expect(authorizationURL.searchParams.get('nonce')).toBe('cic-commitment');
    expect(authorizationURL.searchParams.get('state')).toBe(transaction.state);
    expect(authorizationURL.searchParams.get('code_challenge_method')).toBe('S256');
    expect(authorizationURL.searchParams.get('code_challenge')).toBe(
      base64UrlEncode(new Uint8Array(digest))
    );
    expect(authorizationURL.searchParams.has('code_verifier')).toBe(false);
    expect(authorizationURL.searchParams.get('connection')).toBe('github');
    expect(authorizationURL.searchParams.get('audience')).toBe('https://trust.example.com');
  });

  it.each([undefined, 'https://trust.example.com/auth/google/token'])(
    'validates state and exchanges the code using the saved verifier (exchange: %s)',
    async (tokenExchangeURL) => {
      const idToken = testIDToken();
      const fetchMock = jest
        .spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(discoveryResponse())
        .mockResolvedValueOnce(
          Response.json({
            id_token: idToken,
            access_token: 'access-token',
            token_type: 'Bearer',
          })
        );
      const op = new BrowserOidcOp({ issuer, clientID, redirectURI, tokenExchangeURL });
      await expect(op.requestTokens(mockClaims())).rejects.toThrow('Redirecting');
      const transaction = JSON.parse(sessionStorage.getItem(transactionKey)!);
      location.href = `${redirectURI}?code=authorization-code&state=${transaction.state}`;

      const tokens = await op.handleCallback();
      expect(new TextDecoder().decode(tokens?.idToken)).toBe(idToken);
      expect(new TextDecoder().decode(tokens?.accessToken)).toBe('access-token');
      expect(tokens?.refreshToken).toBeUndefined();
      expect(sessionStorage.getItem(transactionKey)).toBeNull();

      const tokenRequest = fetchMock.mock.calls[1];
      expect(tokenRequest[0]).toBe(tokenExchangeURL ?? `${issuer}oauth/token`);
      const body = tokenRequest[1]?.body as URLSearchParams;
      expect(body.get('grant_type')).toBe('authorization_code');
      expect(body.get('code')).toBe('authorization-code');
      expect(body.get('code_verifier')).toBe(transaction.codeVerifier);
      expect(body.get('redirect_uri')).toBe(redirectURI);
      expect(body.has('client_secret')).toBe(false);
    }
  );

  it('rejects a token response that is not bound to the CIC nonce', async () => {
    jest
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(discoveryResponse())
      .mockResolvedValueOnce(
        Response.json({
          id_token: testIDToken('wrong-nonce'),
          access_token: 'access-token',
          token_type: 'Bearer',
        })
      );
    const op = new BrowserOidcOp({ issuer, clientID, redirectURI });
    await expect(op.requestTokens(mockClaims())).rejects.toThrow('Redirecting');
    const transaction = JSON.parse(sessionStorage.getItem(transactionKey)!);
    location.href = `${redirectURI}?code=authorization-code&state=${transaction.state}`;

    await expect(op.handleCallback()).rejects.toThrow('nonce');
    expect(sessionStorage.getItem(transactionKey)).toBeNull();
  });

  it('rejects mismatched and expired callback transactions before token exchange', async () => {
    const fetchMock = jest.spyOn(globalThis, 'fetch').mockResolvedValue(discoveryResponse());
    const op = new BrowserOidcOp({ issuer, clientID, redirectURI });
    await expect(op.requestTokens(mockClaims())).rejects.toThrow('Redirecting');
    location.href = `${redirectURI}?code=authorization-code&state=wrong`;
    await expect(op.handleCallback()).rejects.toThrow('Invalid OAuth state');
    expect(sessionStorage.getItem(transactionKey)).not.toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const pending = JSON.parse(sessionStorage.getItem(transactionKey)!);
    location.href = `${redirectURI}?error=access_denied&state=${pending.state}`;
    await expect(op.handleCallback()).rejects.toThrow('authorization response from the server');
    expect(sessionStorage.getItem(transactionKey)).toBeNull();

    await expect(op.requestTokens(mockClaims())).rejects.toThrow('Redirecting');
    const transaction = JSON.parse(sessionStorage.getItem(transactionKey)!);
    transaction.createdAt = Date.now() - 11 * 60 * 1000;
    sessionStorage.setItem(transactionKey, JSON.stringify(transaction));
    location.href = `${redirectURI}?code=authorization-code&state=${transaction.state}`;
    await expect(op.handleCallback()).rejects.toThrow('transaction expired');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('bounds provider responses while reading them', async () => {
    jest
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response(`{"padding":"${'x'.repeat((1 << 20) + 1)}"}`));
    const op = new BrowserOidcOp({ issuer, clientID, redirectURI });

    await expect(op.requestTokens(mockClaims())).rejects.toThrow('exceeds 1048576 bytes');
    expect(location.assign).not.toHaveBeenCalled();
  });

  it('removes the saved verifier after a failed token exchange', async () => {
    jest
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(discoveryResponse())
      .mockResolvedValueOnce(new Response('', { status: 503 }));
    const op = new BrowserOidcOp({ issuer, clientID, redirectURI });
    await expect(op.requestTokens(mockClaims())).rejects.toThrow('Redirecting');
    const transaction = JSON.parse(sessionStorage.getItem(transactionKey)!);
    location.href = `${redirectURI}?code=authorization-code&state=${transaction.state}`;

    await expect(op.handleCallback()).rejects.toThrow('unexpected HTTP status code');
    expect(sessionStorage.getItem(transactionKey)).toBeNull();
  });

  it('requires exact secure configuration and discovery metadata', async () => {
    for (const tokenExchangeURL of [
      'http://trust.example.com/token',
      'https://user:secret@trust.example.com/token',
      'https://trust.example.com/token?secret=value',
      'https://trust.example.com/token#fragment',
    ]) {
      expect(
        () => new BrowserOidcOp({ issuer, clientID, redirectURI, tokenExchangeURL })
      ).toThrow();
    }
    expect(
      () =>
        new BrowserOidcOp({
          issuer,
          clientID,
          redirectURI,
          tokenExchangeURL: 'http://localhost:8080/auth/google/token',
        })
    ).not.toThrow();
    expect(
      () => new BrowserOidcOp({ issuer: 'http://tenant.example.com', clientID, redirectURI })
    ).toThrow('HTTPS');
    expect(
      () =>
        new BrowserOidcOp({
          issuer,
          clientID,
          redirectURI,
          authorizationParams: { nonce: 'override' },
        })
    ).toThrow('reserved');
    const issuerWithoutSlash = 'https://accounts.example.com';
    expect(new BrowserOidcOp({ issuer: issuerWithoutSlash, clientID, redirectURI }).issuer()).toBe(
      issuerWithoutSlash
    );

    jest
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(discoveryResponse({ issuer: 'https://other.example.com/' }));
    const op = new BrowserOidcOp({ issuer, clientID, redirectURI });
    await expect(op.requestTokens(mockClaims())).rejects.toThrow('does not match');
    expect(location.assign).not.toHaveBeenCalled();
  });

  it('verifies the provider signature, issuer, audience, and CIC nonce', async () => {
    const keyPair = await jose.generateKeyPair('RS256');
    const publicKey = await jose.exportJWK(keyPair.publicKey);
    publicKey.kid = 'provider-key';
    publicKey.alg = 'RS256';
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url.endsWith('/.well-known/openid-configuration')) {
        return discoveryResponse();
      }
      if (url.endsWith('/.well-known/jwks.json')) {
        return Response.json({ keys: [publicKey] });
      }
      throw new Error(`Unexpected request: ${url}`);
    });
    const op = new BrowserOidcOp({ issuer, clientID, redirectURI });
    const claims = mockClaims();
    const token = await new jose.SignJWT({
      iss: issuer,
      sub: 'auth0|user-1',
      aud: clientID,
      nonce: 'cic-commitment',
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'provider-key' })
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(keyPair.privateKey);

    await expect(
      op.verifyIDToken(new TextEncoder().encode(token), claims)
    ).resolves.toBeUndefined();

    const wrongNonce = await new jose.SignJWT({
      iss: issuer,
      sub: 'auth0|user-1',
      aud: clientID,
      nonce: 'different-commitment',
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'provider-key' })
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(keyPair.privateKey);
    await expect(op.verifyIDToken(new TextEncoder().encode(wrongNonce), claims)).rejects.toThrow(
      'Nonce mismatch'
    );
  });
});
