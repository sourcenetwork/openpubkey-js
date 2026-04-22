// Browser-safe client re-exports. Node-side modules (`client`, `oauth`, `cosigner`) import
// `http` / `crypto` / `child_process`. They're excluded from the root export so bundlers
// targeting browsers don't choke on the Node built-ins. Node consumers should import those
// by path (e.g. `@sourcenetwork/openpubkey-js/client/client.js` once subpath exports land).
export * from './client-browser.js';
