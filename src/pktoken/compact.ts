import { splitCompact } from '../oidc/oidc.js';
import { joinBytes, concatBytes, bytesEqual } from '../util/bytes.js';

/**
 * Creates a compact representation of a PK Token from a list of tokens
 */
export function compactPKToken(tokens: Uint8Array[], freshIDToken?: Uint8Array): Uint8Array {
  if (tokens.length === 0) {
    throw new Error('No tokens provided');
  }
  const compact: Uint8Array[] = [];
  let payload: Uint8Array | null = null;
  for (const tok of tokens) {
    const [tokProtected, tokPayload, tokSig] = splitCompact(tok);
    if (payload !== null) {
      if (!bytesEqual(payload, tokPayload)) {
        throw new Error(
          `Payloads in tokens are not the same: ${new TextDecoder().decode(payload)} vs ${new TextDecoder().decode(tokPayload)}`
        );
      }
    } else {
      payload = tokPayload;
    }
    compact.push(tokProtected, tokSig);
  }
  compact.unshift(payload!);
  let pktCom = joinBytes(':'.charCodeAt(0), ...compact);
  if (freshIDToken) {
    const freshStr = new TextDecoder().decode(freshIDToken);
    if (freshStr.split('.').length !== 3) {
      throw new Error('Invalid refreshed ID Token');
    }
    pktCom = concatBytes(pktCom, new TextEncoder().encode('.'), freshIDToken);
  }
  return pktCom;
}

/**
 * Breaks a compact representation of a PK Token into its constituent tokens
 */
export function splitCompactPKToken(pktCom: Uint8Array): [Uint8Array[], Uint8Array | null] {
  const pktComStr = new TextDecoder().decode(pktCom);
  const dotIndex = pktComStr.indexOf('.');
  let tokensBytes: string;
  let freshIDToken: Uint8Array | null = null;
  if (dotIndex !== -1) {
    tokensBytes = pktComStr.substring(0, dotIndex);
    const freshStr = pktComStr.substring(dotIndex + 1);
    if (freshStr.split('.').length !== 3) {
      throw new Error('Invalid refreshed ID Token');
    }
    freshIDToken = new TextEncoder().encode(freshStr);
  } else {
    tokensBytes = pktComStr;
  }
  const tokensParts = tokensBytes.split(':');
  if (tokensParts.length < 3 || tokensParts.length % 2 !== 1) {
    throw new Error(`Invalid number of segments: got ${tokensParts.length}`);
  }
  const tokens: Uint8Array[] = [];
  const payload = tokensParts[0];
  for (let i = 1; i < tokensParts.length; i += 2) {
    const token = `${tokensParts[i]}.${payload}.${tokensParts[i + 1]}`;
    tokens.push(new TextEncoder().encode(token));
  }
  return [tokens, freshIDToken];
}
