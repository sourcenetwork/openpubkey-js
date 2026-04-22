// Main exports for the OpenPubKey TypeScript library

// Core types and utilities
export * from './util/index.js';
export * from './oidc/index.js';
export * from './pktoken/index.js';

// Discovery and providers
export * from './discover/index.js';
export * from './providers/index.js';

// Client, verifier, and cosigner
export * from './client/index.js';
export * from './verifier/index.js';
export * from './cosigner/index.js';

// Bearer token helper for trust-api-style consumers
export * from './bearer/index.js';

// Browser-specific exports
export {
  randomBytes,
  randomHex,
  isBrowserEnvironment,
  b64SHA3_256,
} from './util/crypto.js';
export {
  GoogleBrowserOp,
  newGoogleBrowserOp,
  newGoogleBrowserOpWithOptions,
  getDefaultGoogleBrowserOpOptions,
  type GoogleBrowserOptions,
} from './providers/google-browser.js';
export {
  OpkClientBrowser,
  type ClientBrowserOptions,
} from './client/client-browser.js';
export {
  newSignedMessageBrowser,
  verifySignedMessageBrowser,
  type VerifyOptions as VerifyOptionsBrowser,
} from './pktoken/osm-browser.js';
