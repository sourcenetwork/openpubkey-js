import * as net from 'net';
import * as crypto from 'crypto';

/**
 * Attempts to find an available port on localhost from the provided redirect URIs
 *
 * @param redirectURIs - Array of redirect URIs to try
 * @returns The chosen redirect URI, the server listening on that port, and any error
 */
export async function findAvailablePort(
  redirectURIs: string[]
): Promise<{ redirectURI: URL; server: net.Server }> {
  let lastError: Error | null = null;
  for (const uriStr of redirectURIs) {
    try {
      const redirectURI = new URL(uriStr);
      const host = redirectURI.hostname;
      if (
        host !== 'localhost' &&
        host !== '127.0.0.1' &&
        host !== '0:0:0:0:0:0:0:1' &&
        host !== '::1'
      ) {
        throw new Error(`redirectURI must be localhost, got: ${host}`);
      }
      const port = redirectURI.port || '80';
      const server = net.createServer();
      await new Promise<void>((resolve, reject) => {
        server.once('error', (err) => {
          reject(err);
        });
        server.listen(parseInt(port, 10), 'localhost', () => {
          resolve();
        });
      });
      return { redirectURI, server };
    } catch (err) {
      lastError = err as Error;
      continue;
    }
  }
  throw new Error(
    `Failed to start a listener for the callback from the OP: ${lastError?.message || 'unknown error'}`
  );
}

/**
 * Cookie handler configuration
 *
 * Note: The Go implementation uses gorilla/sessions with hash keys and block keys
 * for secure cookie handling. In Node.js/TypeScript, we provide the key generation
 * but leave the actual cookie handling to the HTTP framework being used.
 */
export interface CookieConfig {
  hashKey: Buffer;
  blockKey: Buffer;
  secure: boolean;
}

/**
 * Configures cookie handler with random keys
 *
 * OpenPubkey uses a localhost redirect URI to receive the authcode from the OP.
 * Localhost redirects use http not https. Thus, cookies should not be set as
 * secure-only. This should be changed if OpenPubkey adds support for non-localhost
 * redirect URIs.
 *
 * @returns Cookie configuration with generated keys
 */
export function configCookieHandler(): CookieConfig {
  // Generate random keys for cookie encryption
  // Hash key should be 64 bytes for HMAC-SHA256
  const hashKey = crypto.randomBytes(64);
  // Block key should be 32 bytes for AES-256
  const blockKey = crypto.randomBytes(32);
  return {
    hashKey,
    blockKey,
    secure: false, // Not secure since we use localhost HTTP
  };
}

/**
 * Helper to get environment variable with error checking
 *
 * @param name - Environment variable name
 * @returns The value of the environment variable
 * @throws Error if the environment variable is not set
 */
export function getEnvVar(name: string): string {
  const value = process.env[name];
  if (value === undefined) {
    throw new Error(`"${name}" environment variable not set`);
  }
  return value;
}
