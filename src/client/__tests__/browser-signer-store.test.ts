import { webcrypto } from 'node:crypto';
import 'fake-indexeddb/auto';
import {
  deleteBrowserSigner,
  loadBrowserSigner,
  saveBrowserSigner,
} from '../browser-signer-store.js';

Object.defineProperty(globalThis, 'crypto', {
  configurable: true,
  value: webcrypto,
});

describe('browser signer storage', () => {
  it('round-trips a non-extractable signing key', async () => {
    const id = `signer-${crypto.randomUUID()}`;
    const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'sign',
      'verify',
    ]);

    await saveBrowserSigner(id, keyPair.privateKey);
    const signer = await loadBrowserSigner(id);

    expect(signer).not.toBeNull();
    expect(signer?.extractable).toBe(false);
    expect(signer?.type).toBe('private');
    await expect(crypto.subtle.exportKey('jwk', signer!)).rejects.toThrow();

    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      signer!,
      new TextEncoder().encode('openpubkey')
    );
    expect(signature.byteLength).toBeGreaterThan(0);

    await deleteBrowserSigner(id);
    await expect(loadBrowserSigner(id)).resolves.toBeNull();
  });

  it('rejects extractable private keys', async () => {
    const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ]);

    await expect(saveBrowserSigner('extractable', keyPair.privateKey)).rejects.toThrow(
      'non-extractable private signing key'
    );
  });
});
