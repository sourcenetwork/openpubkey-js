import * as http from 'http';
import * as crypto from 'crypto';
import { URL } from 'url';
import type { Tokens } from '../oidc/tokens.js';
import type { Claims } from '../pktoken/clientinstance/claims.js';
import { discoverOIDCConfig } from '../discover/discover.js';
import { openUrl } from '../util/launch.js';

// OAuth constants
const PKCE_VERIFIER_BYTES = 32;
const STATE_PARAM_BYTES = 16;
const DEFAULT_LOCALHOST_PORT = 3000;
const OAUTH_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
const SERVER_CLOSE_DELAY_MS = 100;

/**
 * OAuth configuration options
 */
export interface OAuthOptions {
  issuer: string;
  clientID: string;
  clientSecret?: string;
  redirectURIs: string[];
  scopes: string[];
  promptType?: string;
  accessType?: string;
  openBrowser?: boolean;
}

/**
 * PKCE (Proof Key for Code Exchange) challenge
 */
interface PKCEChallenge {
  verifier: string;
  challenge: string;
  method: string;
}

/**
 * OAuth state
 */
interface OAuthState {
  state: string;
  codeVerifier: string;
  nonce: string;
}

/**
 * Generates a PKCE code verifier and challenge
 */
function generatePKCE(): PKCEChallenge {
  // Generate random verifier (43-128 characters)
  const verifier = crypto.randomBytes(PKCE_VERIFIER_BYTES).toString('base64url');
  // Create challenge from verifier using SHA256
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return {
    verifier,
    challenge,
    method: 'S256',
  };
}

/**
 * Generates a random state parameter
 */
function generateState(): string {
  return crypto.randomBytes(STATE_PARAM_BYTES).toString('base64url');
}

/**
 * Finds an available port from the redirect URIs
 */
function findAvailablePort(redirectURIs: string[]): Promise<{ uri: URL; port: number }> {
  return new Promise((resolve, reject) => {
    for (const uriStr of redirectURIs) {
      const uri = new URL(uriStr);
      if (uri.hostname === 'localhost' || uri.hostname === '127.0.0.1') {
        const port = parseInt(uri.port) || DEFAULT_LOCALHOST_PORT;
        resolve({ uri, port });
        return;
      }
    }
    reject(new Error('No localhost redirect URI found'));
  });
}

/**
 * OAuth flow manager for browser-based authentication
 */
export class OAuthFlow {
  private options: OAuthOptions;
  private server?: http.Server;
  private discoveryConfig?: { authorization_endpoint: string; token_endpoint: string };

  constructor(options: OAuthOptions) {
    this.options = {
      ...options,
      openBrowser: options.openBrowser !== false,
    };
  }

  /**
   * Performs the OAuth authorization code flow with PKCE
   * @param cic - Client Instance Claims (hash will be used as nonce)
   * @returns The tokens from the OAuth provider
   */
  async requestTokens(cic: Claims): Promise<Tokens> {
    // Get CIC hash for nonce
    const nonceBytes = await cic.hash();
    const nonce = new TextDecoder().decode(nonceBytes);
    // Discover OIDC configuration
    this.discoveryConfig = await discoverOIDCConfig(this.options.issuer);
    // Generate PKCE challenge
    const pkce = generatePKCE();
    const state = generateState();
    // Store state
    const oauthState: OAuthState = {
      state,
      codeVerifier: pkce.verifier,
      nonce,
    };
    // Find available port
    const { uri: redirectURI, port } = await findAvailablePort(this.options.redirectURIs);
    // Start local server for callback
    const tokens = await this.startCallbackServer(
      redirectURI,
      port,
      oauthState,
      pkce.challenge,
      nonce
    );
    return tokens;
  }

  /**
   * Starts the local callback server
   */
  private startCallbackServer(
    redirectURI: URL,
    port: number,
    oauthState: OAuthState,
    codeChallenge: string,
    nonce: string
  ): Promise<Tokens> {
    return new Promise((resolve, reject) => {
      // eslint-disable-next-line prefer-const -- assigned after server creation, before it's needed
      let timeoutHandle: NodeJS.Timeout;
      this.server = http.createServer(async (req, res) => {
        const reqUrl = new URL(req.url || '/', `http://localhost:${port}`);
        if (reqUrl.pathname === '/login') {
          // Build authorization URL
          const authUrl = this.buildAuthorizationURL(
            redirectURI.toString(),
            oauthState.state,
            codeChallenge,
            nonce
          );
          // Redirect to authorization endpoint
          res.writeHead(302, { Location: authUrl });
          res.end();
          // Open browser if configured
          if (this.options.openBrowser) {
            await openUrl(authUrl);
          }
        } else if (reqUrl.pathname === redirectURI.pathname) {
          // Handle callback
          clearTimeout(timeoutHandle);
          const code = reqUrl.searchParams.get('code');
          const returnedState = reqUrl.searchParams.get('state');
          const error = reqUrl.searchParams.get('error');
          const errorDescription = reqUrl.searchParams.get('error_description');
          if (error) {
            res.writeHead(400, { 'Content-Type': 'text/html' });
            res.end(`<h1>Authentication Error</h1><p>${error}: ${errorDescription}</p>`);
            this.server?.close();
            reject(new Error(`OAuth error: ${error} - ${errorDescription}`));
            return;
          }
          if (!code) {
            res.writeHead(400, { 'Content-Type': 'text/html' });
            res.end('<h1>Error</h1><p>No authorization code received</p>');
            this.server?.close();
            reject(new Error('No authorization code received'));
            return;
          }
          if (returnedState !== oauthState.state) {
            res.writeHead(400, { 'Content-Type': 'text/html' });
            res.end('<h1>Error</h1><p>State mismatch</p>');
            this.server?.close();
            reject(new Error('State parameter mismatch'));
            return;
          }
          // Exchange code for tokens
          try {
            const tokens = await this.exchangeCodeForTokens(
              code,
              redirectURI.toString(),
              oauthState.codeVerifier
            );
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(
              '<h1>Success!</h1><p>You may now close this window and return to the application.</p>'
            );
            // Give the response time to be sent before closing
            setTimeout(() => {
              this.server?.close();
              resolve(tokens);
            }, SERVER_CLOSE_DELAY_MS);
          } catch (error) {
            res.writeHead(500, { 'Content-Type': 'text/html' });
            res.end(`<h1>Error</h1><p>Failed to exchange code for tokens: ${error}</p>`);
            this.server?.close();
            reject(error);
          }
        } else {
          res.writeHead(404);
          res.end('Not found');
        }
      });
      this.server.listen(port, () => {
        // Navigate to login
        const loginUrl = `http://localhost:${port}/login`;
        if (this.options.openBrowser) {
          openUrl(loginUrl);
        }
      });
      // Set timeout
      timeoutHandle = setTimeout(() => {
        this.server?.close();
        reject(new Error('OAuth flow timed out after 5 minutes'));
      }, OAUTH_TIMEOUT_MS);
      this.server.on('error', (error) => {
        clearTimeout(timeoutHandle);
        reject(error);
      });
    });
  }

  /**
   * Builds the authorization URL
   */
  private buildAuthorizationURL(
    redirectURI: string,
    state: string,
    codeChallenge: string,
    nonce: string
  ): string {
    if (!this.discoveryConfig) {
      throw new Error('Discovery config not loaded');
    }
    const url = new URL(this.discoveryConfig.authorization_endpoint);
    url.searchParams.set('client_id', this.options.clientID);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('redirect_uri', redirectURI);
    url.searchParams.set('scope', this.options.scopes.join(' '));
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    if (this.options.promptType) {
      url.searchParams.set('prompt', this.options.promptType);
    }
    if (this.options.accessType) {
      url.searchParams.set('access_type', this.options.accessType);
    }
    return url.toString();
  }

  /**
   * Exchanges authorization code for tokens
   */
  private async exchangeCodeForTokens(
    code: string,
    redirectURI: string,
    codeVerifier: string
  ): Promise<Tokens> {
    if (!this.discoveryConfig) {
      throw new Error('Discovery config not loaded');
    }
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectURI,
      client_id: this.options.clientID,
      code_verifier: codeVerifier,
    });
    // Add client secret if provided
    if (this.options.clientSecret) {
      params.set('client_secret', this.options.clientSecret);
    }
    const response = await fetch(this.discoveryConfig.token_endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Token exchange failed: ${response.status} - ${errorText}`);
    }
    const data = (await response.json()) as {
      id_token: string;
      access_token?: string;
      refresh_token?: string;
    };
    return {
      idToken: new TextEncoder().encode(data.id_token),
      accessToken: data.access_token ? new TextEncoder().encode(data.access_token) : undefined,
      refreshToken: data.refresh_token ? new TextEncoder().encode(data.refresh_token) : undefined,
    };
  }

  /**
   * Refreshes tokens using a refresh token
   */
  async refreshTokens(refreshToken: Uint8Array): Promise<Tokens> {
    if (!this.discoveryConfig) {
      this.discoveryConfig = await discoverOIDCConfig(this.options.issuer);
    }
    const refreshTokenStr = new TextDecoder().decode(refreshToken);
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshTokenStr,
      client_id: this.options.clientID,
    });
    if (this.options.clientSecret) {
      params.set('client_secret', this.options.clientSecret);
    }
    const response = await fetch(this.discoveryConfig.token_endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Token refresh failed: ${response.status} - ${errorText}`);
    }
    const data = (await response.json()) as {
      id_token: string;
      access_token?: string;
      refresh_token?: string;
    };
    return {
      idToken: new TextEncoder().encode(data.id_token),
      accessToken: data.access_token ? new TextEncoder().encode(data.access_token) : undefined,
      refreshToken: data.refresh_token ? new TextEncoder().encode(data.refresh_token) : undefined,
    };
  }

  /**
   * Closes the OAuth server
   */
  close(): void {
    this.server?.close();
  }
}
