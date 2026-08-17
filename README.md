# openpubkey-js

TypeScript implementation of the [OpenPubKey](https://github.com/openpubkey/openpubkey) protocol.

This library is a complete rewrite of the official Go implementation, providing the same functionality for JavaScript/TypeScript environments. It works in both Node.js and browsers.

## Installation

```bash
npm install @sourcenetwork/openpubkey-js
```

## What is OpenPubKey?

OpenPubKey binds cryptographic keys to OpenID Connect identities without requiring modifications to identity providers.

## Usage

### Node.js

```typescript
import { OpkClient, GoogleOp, Verifier } from '@sourcenetwork/openpubkey-js';

// Create a client with Google as the identity provider
const op = new GoogleOp();
const client = await OpkClient.newClient(op);

// Authenticate and get a PK Token
const pkToken = await client.auth();

// Sign a message
const signedMessage = await pkToken.newSignedMessage(
  new TextEncoder().encode('Hello, World!'),
  client.getSigner()
);

// Verify the PK Token (throws on failure)
const verifier = await Verifier.newVerifier(op);
await verifier.verifyPKToken(pkToken);
```

### Browser

```typescript
import {
  OpkClientBrowser,
  GoogleBrowserOp,
} from '@sourcenetwork/openpubkey-js';

// Create browser-compatible client
const op = new GoogleBrowserOp({
  clientID: 'your-google-client-id',
  redirectURI: 'https://yourapp.com/callback',
});

const client = await OpkClientBrowser.newClient(op);

// This will redirect to Google for authentication
await client.auth();

// After the provider redirects back to the same origin:
const resumedClient = await OpkClientBrowser.resumeAuth(op);
const pkToken = await resumedClient.completeAuth();
```

The browser flow keeps its private signer as a non-extractable `CryptoKey` in IndexedDB during
the redirect. Callback state contains only a random key reference and public CIC data.

For Auth0 or another standards-compliant provider, use authorization code flow with PKCE:

```typescript
import { BrowserOidcOp, OpkClientBrowser } from '@sourcenetwork/openpubkey-js';

const op = new BrowserOidcOp({
  issuer: 'https://example.auth0.com/',
  clientID: 'your-client-id',
  redirectURI: 'https://app.example.com/callback',
});

const client = await OpkClientBrowser.newClient(op);
await client.auth();

const resumedClient = await OpkClientBrowser.resumeAuth(op);
const pkToken = await resumedClient.completeAuth();
```

The provider must return the requested nonce unchanged in its ID token. The implementation validates
OIDC state, S256 PKCE, discovery metadata, issuer, audience, signature, expiry, and the OpenPubKey
CIC commitment. It never requests or returns a browser refresh token.

## Supported Identity Providers

- Google (Node.js and Browser)
- GitHub Actions
- GitLab CI
- Azure
- Generic OIDC providers

## Features

- **PK Tokens**: Create and verify OpenPubKey tokens
- **GQ Signatures**: Privacy-preserving signatures using the GQ scheme
- **Cosigners**: Multi-factor authentication support
- **Compact Format**: Efficient token serialization

## API Reference

### Core Classes

- `OpkClient` / `OpkClientBrowser` - Main client for authentication
- `PKToken` - OpenPubKey token containing identity and key binding
- `Verifier` - Verify PK Tokens and signatures
- `Claims` - Client Instance Claims for key binding

### Providers

- `GoogleOp` / `GoogleBrowserOp` - Google OpenID Connect
- `GitHubOp` - GitHub Actions OIDC
- `GitLabOp` / `GitLabCIOp` - GitLab OIDC
- `AzureOp` - Azure AD

### Utils

- `gq256SignJWT` / `gq256VerifyJWT` - GQ signature operations
- `compactPKToken` / `splitCompactPKToken` - Token serialization

## Requirements

- Node.js >= 18.0.0
- For browsers: modern browsers with Web Crypto API support

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Lint
npm run lint
```

## Attribution

This library is a TypeScript port of the [OpenPubKey](https://github.com/openpubkey/openpubkey) Go library that follows the same specification and maintains API compatibility.

## License

Apache-2.0
