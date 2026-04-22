import * as jose from 'jose';
import * as nodeCryptoModule from 'crypto';
import { buildBearerToken } from '../bearer.js';
import { PKToken } from '../../pktoken/pktoken.js';

/**
 * genNodeKeyPair is the Node-native equivalent of genKeyPair so tests can pick any of the
 * three JWS algorithm families (EC P-256, EC secp256k1, Ed25519) on a single runtime. The
 * browser path is exercised by the shared jose signer behaviour — jose accepts both
 * CryptoKey and KeyObject.
 */
function genNodeKeyPair(kind: 'p256' | 'secp256k1' | 'ed25519' | 'rsa'): nodeCryptoModule.KeyObject {
  switch (kind) {
    case 'p256':
      return nodeCryptoModule.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
    case 'secp256k1':
      return nodeCryptoModule.generateKeyPairSync('ec', { namedCurve: 'secp256k1' }).privateKey;
    case 'ed25519':
      return nodeCryptoModule.generateKeyPairSync('ed25519').privateKey;
    case 'rsa':
      return nodeCryptoModule.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  }
}

async function decodeJwtPayload(jws: string): Promise<Record<string, unknown>> {
  const [, payloadB64] = jws.split('.');
  const payloadBytes = jose.base64url.decode(payloadB64);
  return JSON.parse(new TextDecoder().decode(payloadBytes));
}

function decodeJwtHeader(jws: string): Record<string, unknown> {
  const [headerB64] = jws.split('.');
  const headerBytes = jose.base64url.decode(headerB64);
  return JSON.parse(new TextDecoder().decode(headerBytes));
}

describe('buildBearerToken', () => {
  it('produces an ES256 JWT from a P-256 signer and infers the algorithm', async () => {
    const signer = genNodeKeyPair('p256');
    const jws = await buildBearerToken(signer, {
      iss: 'did:key:zDnP256',
      authorizedAccount: 'source1abc',
    });

    const header = decodeJwtHeader(jws);
    const payload = await decodeJwtPayload(jws);
    expect(header.alg).toBe('ES256');
    expect(header.typ).toBe('JWT');
    expect(payload.iss).toBe('did:key:zDnP256');
    expect(payload.authorized_account).toBe('source1abc');
    expect(typeof payload.iat).toBe('number');
    expect(typeof payload.exp).toBe('number');
    // default 10 minute window
    expect((payload.exp as number) - (payload.iat as number)).toBe(600);
  });

  it('infers ES256K from a secp256k1 signer', async () => {
    const signer = genNodeKeyPair('secp256k1');
    const jws = await buildBearerToken(signer, { iss: 'did:key:zQ3secp' });
    const header = decodeJwtHeader(jws);
    expect(header.alg).toBe('ES256K');
  });

  it('infers EdDSA from an Ed25519 signer', async () => {
    const signer = genNodeKeyPair('ed25519');
    const jws = await buildBearerToken(signer, { iss: 'did:key:z6MkEd' });
    const header = decodeJwtHeader(jws);
    expect(header.alg).toBe('EdDSA');
  });

  it('infers RS256 from an RSA signer', async () => {
    const signer = genNodeKeyPair('rsa');
    const jws = await buildBearerToken(signer, { iss: 'did:key:zR256' });
    const header = decodeJwtHeader(jws);
    expect(header.alg).toBe('RS256');
  });

  it('verifies with the matching public key', async () => {
    const { privateKey, publicKey } = nodeCryptoModule.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    });
    const jws = await buildBearerToken(privateKey, { iss: 'did:key:zTest' });
    const { payload } = await jose.jwtVerify(jws, publicKey);
    expect(payload.iss).toBe('did:key:zTest');
  });

  it('honours expiresInSec override', async () => {
    const signer = genNodeKeyPair('p256');
    const jws = await buildBearerToken(signer, {
      iss: 'did:key:z1',
      expiresInSec: 60,
      iat: 1_000_000,
    });
    const payload = await decodeJwtPayload(jws);
    expect(payload.iat).toBe(1_000_000);
    expect(payload.exp).toBe(1_000_060);
  });

  it('honours explicit algorithm override (ES256 -> forced ES256)', async () => {
    const signer = genNodeKeyPair('p256');
    const jws = await buildBearerToken(signer, {
      iss: 'did:key:z1',
      algorithm: 'ES256',
    });
    expect(decodeJwtHeader(jws).alg).toBe('ES256');
  });

  it('omits pkt / authorized_account / provider_token when not supplied', async () => {
    const signer = genNodeKeyPair('p256');
    const jws = await buildBearerToken(signer, { iss: 'did:key:z1' });
    const payload = await decodeJwtPayload(jws);
    expect(payload.authorized_account).toBeUndefined();
    expect(payload.provider_token).toBeUndefined();
    expect(payload.pkt).toBeUndefined();
  });

  it('includes provider_token verbatim when supplied', async () => {
    const signer = genNodeKeyPair('p256');
    const jws = await buildBearerToken(signer, {
      iss: 'did:key:z1',
      providerToken: 'opaque-string',
    });
    const payload = await decodeJwtPayload(jws);
    expect(payload.provider_token).toBe('opaque-string');
  });

  it('compact-serialises the pkToken into the pkt claim as base64url', async () => {
    const signer = genNodeKeyPair('p256');

    // Build a minimal two-signature PKToken (OIDC + CIC) so .compact() has something real to emit.
    const payload = { sub: 'user123', iss: 'https://accounts.google.com' };
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const idHeader = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
    const cicHeader = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'CIC' })).toString('base64url');
    const idToken = new TextEncoder().encode(`${idHeader}.${payloadB64}.sigA`);
    const cicToken = new TextEncoder().encode(`${cicHeader}.${payloadB64}.sigB`);
    const pkt = await PKToken.newPKToken(idToken, cicToken);

    const jws = await buildBearerToken(signer, { iss: 'did:key:z1', pkToken: pkt });
    const bearerPayload = await decodeJwtPayload(jws);

    // pkt claim must decode to the same bytes compactPKToken produces directly.
    const expectedCompact = await pkt.compact();
    const actualCompact = jose.base64url.decode(bearerPayload.pkt as string);
    expect(new TextDecoder().decode(actualCompact)).toBe(new TextDecoder().decode(expectedCompact));
  });

  it('rejects an empty iss', async () => {
    const signer = genNodeKeyPair('p256');
    await expect(buildBearerToken(signer, { iss: '' })).rejects.toThrow(/iss is required/);
  });
});
