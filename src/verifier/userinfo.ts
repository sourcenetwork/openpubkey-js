import type { PKToken } from '../pktoken/pktoken.js';

/**
 * UserInfoRequester enables the retrieval of user info from an OpenID Provider
 * using the access token obtained during authentication. It uses the PK Token
 * to look up the issuer URI for the OpenID Provider and ensures that the subject
 * (sub claim) in the ID token matches the subject in the access token.
 */
export class UserInfoRequester {
  private issuer: string;
  private subject: string;
  private accessToken: string;

  constructor(pkt: PKToken, accessToken: string) {
    this.issuer = pkt.issuer();
    this.subject = pkt.subject();
    this.accessToken = accessToken;
  }

  /**
   * Requests user info from the OpenID Provider's userinfo endpoint
   *
   * Calls the OIDC userinfo endpoint using the access token and verifies
   * that the subject matches the ID token's subject.
   *
   * @returns The userinfo JSON response
   * @throws Error if the request fails or subject doesn't match
   */
  async request(): Promise<string> {
    // Discover the OIDC configuration to get the userinfo endpoint
    const discoveryUrl = `${this.issuer}/.well-known/openid-configuration`;
    const discoveryResponse = await fetch(discoveryUrl);
    if (!discoveryResponse.ok) {
      throw new Error(`Failed to fetch OIDC discovery document: ${discoveryResponse.statusText}`);
    }
    const discoveryDoc = (await discoveryResponse.json()) as {
      userinfo_endpoint?: string;
    };
    if (!discoveryDoc.userinfo_endpoint) {
      throw new Error('No userinfo_endpoint found in OIDC discovery document');
    }
    // Call the userinfo endpoint with the access token
    const userinfoResponse = await fetch(discoveryDoc.userinfo_endpoint, {
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
      },
    });
    if (!userinfoResponse.ok) {
      throw new Error(`Failed to fetch userinfo: ${userinfoResponse.statusText}`);
    }
    const userinfo = (await userinfoResponse.json()) as {
      sub?: string;
      [key: string]: unknown;
    };
    // Verify that the subject in userinfo matches the ID token subject
    if (userinfo.sub !== this.subject) {
      throw new Error(
        `Subject mismatch: ID token has '${this.subject}', userinfo has '${userinfo.sub}'`
      );
    }
    return JSON.stringify(userinfo);
  }
}

/**
 * Creates a new UserInfoRequester from a PK Token and access token
 *
 * @param pkt - The PK Token containing issuer and subject information
 * @param accessToken - The access token to use for the userinfo request
 * @returns A new UserInfoRequester instance
 */
export function newUserInfoRequester(pkt: PKToken, accessToken: string): UserInfoRequester {
  return new UserInfoRequester(pkt, accessToken);
}
