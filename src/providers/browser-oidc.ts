import * as oauth from 'oauth4webapi';
import { PublicKeyFinder, type PublicKeyRecord } from '../discover/discover.js';
import type { Tokens } from '../oidc/tokens.js';
import type { Claims } from '../pktoken/clientinstance/claims.js';
import { DefaultProviderVerifier } from './provider-verifier.js';
import { CommitTypes, type BrowserOpenIdProvider } from './types.js';

const transactionKey = 'opk_oidc_transaction';
const transactionLifetime = 10 * 60 * 1000;
const maxProviderResponseSize = 1 << 20;
const providerRequestOptions = { [oauth.customFetch]: providerFetch };
const reservedAuthorizationParams = new Set([
  'client_id',
  'code_challenge',
  'code_challenge_method',
  'max_age',
  'nonce',
  'redirect_uri',
  'request',
  'request_uri',
  'response_mode',
  'response_type',
  'scope',
  'state',
]);

export interface BrowserOidcOptions {
  issuer: string;
  clientID: string;
  redirectURI: string;
  scopes?: string[];
  authorizationParams?: Record<string, string>;
}

interface NormalizedOptions {
  issuer: string;
  clientID: string;
  redirectURI: string;
  scopes: string[];
  authorizationParams: Record<string, string>;
}

interface OidcTransaction {
  state: string;
  codeVerifier: string;
  nonce: string;
  issuer: string;
  clientID: string;
  redirectURI: string;
  createdAt: number;
}

export class BrowserOidcOp implements BrowserOpenIdProvider {
  private readonly options: NormalizedOptions;
  private readonly client: oauth.Client;
  private readonly publicKeyFinder: PublicKeyFinder;
  private readonly verifier: DefaultProviderVerifier;
  private discoveryConfig?: oauth.AuthorizationServer;

  constructor(options: BrowserOidcOptions) {
    this.options = normalizeOptions(options);
    this.client = { client_id: this.options.clientID };
    this.publicKeyFinder = new PublicKeyFinder(async () => this.fetchJWKS());
    this.verifier = new DefaultProviderVerifier(this.options.issuer, {
      commitType: CommitTypes.NONCE_CLAIM,
      clientID: this.options.clientID,
      skipClientIDCheck: false,
      gqOnly: false,
      discoverPublicKey: this.publicKeyFinder,
    });
  }

  issuer(): string {
    return this.options.issuer;
  }

  async publicKeyByKeyId(keyID: string): Promise<PublicKeyRecord> {
    return this.publicKeyFinder.byKeyID(this.options.issuer, keyID);
  }

  async publicKeyByToken(token: Uint8Array): Promise<PublicKeyRecord> {
    return this.publicKeyFinder.byToken(this.options.issuer, token);
  }

  async requestTokens(cic: Claims): Promise<Tokens> {
    const discovery = await this.discover();
    const authorizationURL = endpoint(discovery.authorization_endpoint, 'authorization');
    const nonce = new TextDecoder().decode(await cic.hash());
    const state = oauth.generateRandomState();
    const codeVerifier = oauth.generateRandomCodeVerifier();
    const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);
    const transaction: OidcTransaction = {
      state,
      codeVerifier,
      nonce,
      issuer: this.options.issuer,
      clientID: this.options.clientID,
      redirectURI: this.options.redirectURI,
      createdAt: Date.now(),
    };
    sessionStorage.setItem(transactionKey, JSON.stringify(transaction));

    for (const [name, value] of Object.entries(this.options.authorizationParams)) {
      authorizationURL.searchParams.set(name, value);
    }
    authorizationURL.searchParams.set('client_id', this.options.clientID);
    authorizationURL.searchParams.set('redirect_uri', this.options.redirectURI);
    authorizationURL.searchParams.set('response_type', 'code');
    authorizationURL.searchParams.set('scope', this.options.scopes.join(' '));
    authorizationURL.searchParams.set('state', state);
    authorizationURL.searchParams.set('nonce', nonce);
    authorizationURL.searchParams.set('code_challenge', codeChallenge);
    authorizationURL.searchParams.set('code_challenge_method', 'S256');
    window.location.assign(authorizationURL.toString());
    throw new Error('Redirecting to OAuth provider...');
  }

  async handleCallback(): Promise<Tokens | null> {
    const callback = new URL(window.location.href);
    const code = callbackParameter(callback.searchParams, 'code');
    const providerError = callbackParameter(callback.searchParams, 'error');
    if (!code && !providerError) {
      return null;
    }

    const transaction = this.loadTransaction();
    if (callbackParameter(callback.searchParams, 'state') !== transaction.state) {
      throw new Error('Invalid OAuth state');
    }
    try {
      const discovery = await this.discover();
      const parameters = oauth.validateAuthResponse(
        discovery,
        this.client,
        callback,
        transaction.state
      );
      const response = await oauth.authorizationCodeGrantRequest(
        discovery,
        this.client,
        oauth.None(),
        parameters,
        this.options.redirectURI,
        transaction.codeVerifier,
        providerRequestOptions
      );
      const result = await oauth.processAuthorizationCodeResponse(
        discovery,
        this.client,
        response,
        { expectedNonce: transaction.nonce, requireIdToken: true }
      );
      if (!result.id_token) {
        throw new Error('OIDC token response is missing an ID token');
      }
      return {
        idToken: new TextEncoder().encode(result.id_token),
        accessToken: new TextEncoder().encode(result.access_token),
        refreshToken: undefined,
      };
    } finally {
      this.clearPendingAuth();
    }
  }

  verifyIDToken(idToken: Uint8Array, cic: Claims): Promise<void> {
    return this.verifier.verifyIDToken(idToken, cic);
  }

  clearPendingAuth(): void {
    sessionStorage.removeItem(transactionKey);
  }

  private loadTransaction(): OidcTransaction {
    const encoded = sessionStorage.getItem(transactionKey);
    if (!encoded) {
      throw new Error('No pending OIDC authentication transaction');
    }
    let value: unknown;
    try {
      value = JSON.parse(encoded);
    } catch {
      throw new Error('Invalid OIDC authentication transaction');
    }
    if (!isTransaction(value)) {
      throw new Error('Invalid OIDC authentication transaction');
    }
    if (
      value.issuer !== this.options.issuer ||
      value.clientID !== this.options.clientID ||
      value.redirectURI !== this.options.redirectURI
    ) {
      throw new Error('OIDC authentication configuration changed during sign-in');
    }
    const age = Date.now() - value.createdAt;
    if (age < 0 || age > transactionLifetime) {
      throw new Error('OIDC authentication transaction expired');
    }
    return value;
  }

  private async discover(): Promise<oauth.AuthorizationServer> {
    if (!this.discoveryConfig) {
      const issuer = new URL(this.options.issuer);
      const response = await oauth.discoveryRequest(issuer, providerRequestOptions);
      const discovery = await oauth.processDiscoveryResponse(issuer, response);
      endpoint(discovery.authorization_endpoint, 'authorization');
      endpoint(discovery.token_endpoint, 'token');
      endpoint(discovery.jwks_uri, 'JWKS');
      this.discoveryConfig = discovery;
    }
    return this.discoveryConfig;
  }

  private async fetchJWKS(): Promise<string> {
    const discovery = await this.discover();
    const url = endpoint(discovery.jwks_uri, 'JWKS');
    const response = await providerFetch(url.toString(), {
      method: 'GET',
      headers: { Accept: 'application/json' },
      redirect: 'manual',
    });
    if (!response.ok) {
      throw new Error(`OIDC JWKS request failed (${response.status})`);
    }
    return response.text();
  }
}

function normalizeOptions(options: BrowserOidcOptions): NormalizedOptions {
  secureURL(options.issuer, 'issuer', false);
  const issuer = options.issuer;
  const clientID = options.clientID.trim();
  if (!clientID) {
    throw new Error('OIDC client ID is required');
  }
  redirectURL(options.redirectURI);
  const scopes = [
    ...new Set((options.scopes ?? ['openid', 'profile', 'email']).map((scope) => scope.trim())),
  ];
  if (scopes.some((scope) => scope === '' || /\s/.test(scope)) || !scopes.includes('openid')) {
    throw new Error('OIDC scopes must contain openid and separate non-empty scope values');
  }
  const authorizationParams = { ...(options.authorizationParams ?? {}) };
  for (const [name, value] of Object.entries(authorizationParams)) {
    if (reservedAuthorizationParams.has(name.toLowerCase())) {
      throw new Error(`OIDC authorization parameter ${name} is reserved`);
    }
    if (!name || typeof value !== 'string') {
      throw new Error('OIDC authorization parameters must be strings with non-empty names');
    }
  }
  return {
    issuer,
    clientID,
    redirectURI: options.redirectURI,
    scopes,
    authorizationParams,
  };
}

function secureURL(value: string, name: string, allowQuery = true): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`OIDC ${name} must be an absolute URL`);
  }
  if (
    value !== value.trim() ||
    parsed.protocol !== 'https:' ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    (!allowQuery && parsed.search !== '') ||
    parsed.hash !== ''
  ) {
    const forbidden = allowQuery
      ? 'credentials or a fragment'
      : 'credentials, a query, or a fragment';
    throw new Error(`OIDC ${name} must be an HTTPS URL without ${forbidden}`);
  }
  return parsed;
}

function redirectURL(value: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('OIDC redirect URI must be an absolute URL');
  }
  const loopback =
    parsed.hostname === 'localhost' ||
    parsed.hostname === '127.0.0.1' ||
    parsed.hostname === '[::1]';
  if (
    value !== value.trim() ||
    (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.hash !== ''
  ) {
    throw new Error(
      'OIDC redirect URI must use HTTPS, or HTTP on loopback, without credentials or a fragment'
    );
  }
  return parsed;
}

function endpoint(value: unknown, name: string): URL {
  if (typeof value !== 'string') {
    throw new Error(`OIDC discovery is missing the ${name} endpoint`);
  }
  return secureURL(value, `${name} endpoint`);
}

async function providerFetch(url: string, options: RequestInit): Promise<Response> {
  const response = await fetch(url, {
    ...options,
    cache: 'no-store',
    credentials: 'omit',
    referrerPolicy: 'no-referrer',
  });
  if (response.type === 'opaqueredirect' || !response.body) {
    return response;
  }
  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > maxProviderResponseSize) {
    await response.body.cancel();
    throw new Error(`OIDC provider response exceeds ${maxProviderResponseSize} bytes`);
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let part = await reader.read();
  while (!part.done) {
    size += part.value.byteLength;
    if (size > maxProviderResponseSize) {
      await reader.cancel();
      throw new Error(`OIDC provider response exceeds ${maxProviderResponseSize} bytes`);
    }
    chunks.push(part.value);
    part = await reader.read();
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

function callbackParameter(params: URLSearchParams, name: string): string | null {
  const values = params.getAll(name);
  if (values.length > 1) {
    throw new Error(`OIDC callback contains duplicate ${name} parameters`);
  }
  return values[0] ?? null;
}

function isTransaction(value: unknown): value is OidcTransaction {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const transaction = value as Partial<OidcTransaction>;
  return (
    typeof transaction.state === 'string' &&
    transaction.state.length >= 32 &&
    typeof transaction.codeVerifier === 'string' &&
    transaction.codeVerifier.length >= 43 &&
    transaction.codeVerifier.length <= 128 &&
    typeof transaction.nonce === 'string' &&
    transaction.nonce !== '' &&
    typeof transaction.issuer === 'string' &&
    typeof transaction.clientID === 'string' &&
    typeof transaction.redirectURI === 'string' &&
    typeof transaction.createdAt === 'number' &&
    Number.isFinite(transaction.createdAt)
  );
}
