import { webcrypto } from 'node:crypto';
import 'fake-indexeddb/auto';
import type { OpenIdProvider } from '../../providers/types.js';
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
    } as unknown as OpenIdProvider;

    const client = await OpkClientBrowser.newClient(op);
    expect(client.getSigner().extractable).toBe(false);

    await expect(client.auth()).rejects.toThrow('Redirecting to provider');
    expect(sessionStorage.getItem('opk_signer_jwk')).toBeNull();
    expect(sessionStorage.getItem('opk_signer_id')).not.toBeNull();

    const resumed = await OpkClientBrowser.resumeAuth(op);
    expect(resumed.getSigner().extractable).toBe(false);
    await expect(crypto.subtle.exportKey('jwk', resumed.getSigner())).rejects.toThrow();
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
    } as unknown as OpenIdProvider;

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
    } as unknown as OpenIdProvider;

    const client = await OpkClientBrowser.newClient(op, {
      signer: keyPair.privateKey,
      algorithm: KeyAlgorithm.RS256,
    });

    expect(client.getSigner().extractable).toBe(false);
    await expect(client.auth()).rejects.toThrow('Redirecting to provider');
    await expect(OpkClientBrowser.resumeAuth(op)).resolves.toBeDefined();
  });
});
