import { webcrypto } from 'node:crypto';
import { jest } from '@jest/globals';
import 'fake-indexeddb/auto';
import type { BrowserOpenIdProvider } from '../../providers/types.js';
import { KeyAlgorithm } from '../../util/crypto.js';
import { OpkClientBrowser } from '../client-browser.js';

Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: webcrypto,
});

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

Object.defineProperty(globalThis, 'sessionStorage', {
  configurable: true,
  value: new MemoryStorage(),
});

describe('OpkClientBrowser signer lifecycle', () => {
  afterEach(async () => {
    await OpkClientBrowser.clearStoredAuth();
    sessionStorage.clear();
  });

  it('resumes authentication without exporting the private key', async () => {
    const op = {
      requestTokens: async () => {
        throw new Error('Redirecting to provider');
      },
    } as unknown as BrowserOpenIdProvider;

    const client = await OpkClientBrowser.newClient(op);
    expect(client.getSigner().extractable).toBe(false);

    await expect(client.auth()).rejects.toThrow('Redirecting to provider');
    expect(sessionStorage.getItem('opk_signer_jwk')).toBeNull();
    expect(sessionStorage.getItem('opk_signer_id')).not.toBeNull();

    const resumed = await OpkClientBrowser.resumeAuth(op);
    expect(resumed.getSigner().extractable).toBe(false);
    await expect(crypto.subtle.exportKey('jwk', resumed.getSigner())).rejects.toThrow();
  });

  it('does not persist signer state when CIC creation fails', async () => {
    const op = {
      requestTokens: async () => {
        throw new Error('Redirecting to provider');
      },
    } as unknown as BrowserOpenIdProvider;
    const client = await OpkClientBrowser.newClient(op);

    await expect(client.auth({ extraClaims: { alg: 'ES256' } })).rejects.toThrow(
      'Use of reserved header name'
    );

    expect(sessionStorage.getItem('opk_signer_id')).toBeNull();
    expect(sessionStorage.getItem('opk_algorithm')).toBeNull();
    expect(sessionStorage.getItem('opk_cic_protected')).toBeNull();
  });

  it('converts a provided extractable signer before authentication', async () => {
    const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ]);
    const op = {
      requestTokens: async () => {
        throw new Error('Redirecting to provider');
      },
    } as unknown as BrowserOpenIdProvider;

    const client = await OpkClientBrowser.newClient(op, {
      signer: keyPair.privateKey,
      algorithm: KeyAlgorithm.ES256,
    });

    expect(client.getSigner().extractable).toBe(false);
    await expect(client.auth()).rejects.toThrow('Redirecting to provider');
    await expect(OpkClientBrowser.resumeAuth(op)).resolves.toBeDefined();
  });

  it('derives the public key from an extractable RSA signer', async () => {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify']
    );
    const op = {
      requestTokens: async () => {
        throw new Error('Redirecting to provider');
      },
    } as unknown as BrowserOpenIdProvider;

    const client = await OpkClientBrowser.newClient(op, {
      signer: keyPair.privateKey,
      algorithm: KeyAlgorithm.RS256,
    });

    expect(client.getSigner().extractable).toBe(false);
    await expect(client.auth()).rejects.toThrow('Redirecting to provider');

    const cic = JSON.parse(sessionStorage.getItem('opk_cic_protected')!);
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      cic.upk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true,
      ['verify']
    );
    const content = new TextEncoder().encode('openpubkey');
    const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', client.getSigner(), content);
    await expect(
      crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey, signature, content)
    ).resolves.toBe(true);

    await expect(OpkClientBrowser.resumeAuth(op)).resolves.toBeDefined();
  });

  it('requires a public key with a non-extractable signer', async () => {
    const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
      'verify',
    ]);

    await expect(
      OpkClientBrowser.newClient({} as BrowserOpenIdProvider, {
        signer: keyPair.privateKey,
        algorithm: KeyAlgorithm.ES256,
      })
    ).rejects.toThrow('A public key must be provided');
  });

  it('rejects a public key that does not match the signer', async () => {
    const signerPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify']
    );
    const otherPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify']
    );

    await expect(
      OpkClientBrowser.newClient({} as BrowserOpenIdProvider, {
        signer: signerPair.privateKey,
        publicKey: otherPair.publicKey,
        algorithm: KeyAlgorithm.ES256,
      })
    ).rejects.toThrow('does not match the signer');
  });

  it('preserves an authentication error when cleanup also fails', async () => {
    const openSpy = jest.spyOn(indexedDB, 'open').mockImplementation(() => {
      throw new Error('Cleanup failed');
    });
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      sessionStorage.setItem('opk_signer_id', 'unavailable-signer');
      const client = await OpkClientBrowser.newClient({
        handleCallback: () => null,
      } as unknown as BrowserOpenIdProvider);

      await expect(client.completeAuth()).rejects.toThrow('No tokens found in callback');
      expect(consoleSpy).toHaveBeenCalledWith(
        'Failed to clear browser authentication state',
        expect.any(Error)
      );
    } finally {
      openSpy.mockRestore();
      consoleSpy.mockRestore();
    }
  });
});
