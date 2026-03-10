import * as crypto from 'crypto';
import * as fs from 'fs/promises';

/**
 * Converts an ECDSA private key to PEM format (X.509/PKCS#8).
 *
 * @param sk - The private key object
 * @returns The PEM-encoded private key bytes
 */
export function skToX509Bytes(sk: crypto.KeyObject): Uint8Array {
  const pemStr = sk.export({ type: 'pkcs8', format: 'pem' }) as string;
  return new TextEncoder().encode(pemStr);
}

/**
 * Writes a private key to a file in PEM format.
 *
 * @param fpath - The file path to write to
 * @param sk - The private key object
 */
export async function writeSKFile(fpath: string, sk: crypto.KeyObject): Promise<void> {
  const pemBytes = skToX509Bytes(sk);
  await fs.writeFile(fpath, pemBytes, { mode: 0o600 });
}

/**
 * Reads a private key from a PEM file.
 *
 * @param fpath - The file path to read from
 * @returns The private key object
 */
export async function readSKFile(fpath: string): Promise<crypto.KeyObject> {
  const pemBytes = await fs.readFile(fpath);
  const pemStr = new TextDecoder().decode(pemBytes);
  // Import the private key from PEM format
  const privateKey = crypto.createPrivateKey({
    key: pemStr,
    format: 'pem',
  });
  return privateKey;
}
