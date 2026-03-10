import {
  newJws,
  addSignature,
  getToken,
  getTokenByTyp,
  getTyp,
  getProtectedClaims,
  type Signature,
} from '../jws.js';
import { base64UrlEncode } from '../../util/base64.js';

describe('JWS Utils', () => {
  const createMockJwt = (header: Record<string, unknown>, payload: Record<string, unknown>) => {
    const headerB64 = base64UrlEncode(JSON.stringify(header));
    const payloadB64 = base64UrlEncode(JSON.stringify(payload));
    const sig = base64UrlEncode('mock-signature');
    return `${headerB64}.${payloadB64}.${sig}`;
  };

  describe('newJws', () => {
    it('should create an empty JWS structure', () => {
      const jws = newJws();
      expect(jws.payload).toBe('');
      expect(jws.signatures).toEqual([]);
    });
  });

  describe('addSignature', () => {
    it('should add a signature from a compact JWT', () => {
      const jws = newJws();
      const jwt = createMockJwt({ alg: 'ES256', typ: 'JWT' }, { sub: 'user' });

      addSignature(jws, jwt);

      expect(jws.signatures.length).toBe(1);
      expect(jws.payload).not.toBe('');
    });

    it('should add multiple signatures with same payload', () => {
      const payload = { sub: 'user' };
      const jwt1 = createMockJwt({ alg: 'ES256', typ: 'JWT' }, payload);
      const jwt2 = createMockJwt({ alg: 'ES256', typ: 'CIC' }, payload);

      const jws = newJws();
      addSignature(jws, jwt1);
      addSignature(jws, jwt2);

      expect(jws.signatures.length).toBe(2);
    });

    it('should throw for mismatched payloads', () => {
      const jws = newJws();
      const jwt1 = createMockJwt({ alg: 'ES256' }, { sub: 'user1' });
      const jwt2 = createMockJwt({ alg: 'ES256' }, { sub: 'user2' });

      addSignature(jws, jwt1);
      expect(() => addSignature(jws, jwt2)).toThrow('does not match existing payload');
    });

    it('should add public header when provided', () => {
      const jws = newJws();
      const jwt = createMockJwt({ alg: 'ES256' }, { sub: 'user' });

      addSignature(jws, jwt, { publicHeader: { extra: 'value' } });

      expect(jws.signatures[0].header).toEqual({ extra: 'value' });
    });

    it('should accept Uint8Array token', () => {
      const jws = newJws();
      const jwt = new TextEncoder().encode(createMockJwt({ alg: 'ES256' }, { sub: 'user' }));

      addSignature(jws, jwt);

      expect(jws.signatures.length).toBe(1);
    });
  });

  describe('getToken', () => {
    it('should get token by index', () => {
      const jws = newJws();
      const jwt = createMockJwt({ alg: 'ES256' }, { sub: 'user' });
      addSignature(jws, jwt);

      const token = getToken(jws, 0);
      expect(token).toBeInstanceOf(Uint8Array);
      expect(new TextDecoder().decode(token)).toBe(jwt);
    });

    it('should throw for out of bounds index', () => {
      const jws = newJws();
      expect(() => getToken(jws, 0)).toThrow('No signature at index 0');
      expect(() => getToken(jws, -1)).toThrow('No signature at index -1');
    });
  });

  describe('getTokenByTyp', () => {
    it('should find token by typ claim', () => {
      const jws = newJws();
      const payload = { sub: 'user' };
      const jwtToken = createMockJwt({ alg: 'ES256', typ: 'JWT' }, payload);
      const cicToken = createMockJwt({ alg: 'ES256', typ: 'CIC' }, payload);

      addSignature(jws, jwtToken);
      addSignature(jws, cicToken);

      const found = getTokenByTyp(jws, 'CIC');
      expect(found).not.toBeNull();
      expect(new TextDecoder().decode(found!)).toBe(cicToken);
    });

    it('should return null when typ not found', () => {
      const jws = newJws();
      const jwt = createMockJwt({ alg: 'ES256', typ: 'JWT' }, { sub: 'user' });
      addSignature(jws, jwt);

      const found = getTokenByTyp(jws, 'CIC');
      expect(found).toBeNull();
    });

    it('should throw for duplicate typ values', () => {
      const jws = newJws();
      const payload = { sub: 'user' };
      const jwt1 = createMockJwt({ alg: 'ES256', typ: 'JWT' }, payload);
      const jwt2 = createMockJwt({ alg: 'RS256', typ: 'JWT' }, payload);

      addSignature(jws, jwt1);
      addSignature(jws, jwt2);

      expect(() => getTokenByTyp(jws, 'JWT')).toThrow('More than one token found');
    });
  });

  describe('getTyp', () => {
    it('should get typ from signature', () => {
      const headerB64 = base64UrlEncode(JSON.stringify({ alg: 'ES256', typ: 'JWT' }));
      const sig: Signature = {
        protected: headerB64,
        signature: 'sig',
      };

      expect(getTyp(sig)).toBe('JWT');
    });

    it('should return empty string when typ not present', () => {
      const headerB64 = base64UrlEncode(JSON.stringify({ alg: 'ES256' }));
      const sig: Signature = {
        protected: headerB64,
        signature: 'sig',
      };

      expect(getTyp(sig)).toBe('');
    });
  });

  describe('getProtectedClaims', () => {
    it('should parse protected claims', () => {
      const headerB64 = base64UrlEncode(
        JSON.stringify({
          alg: 'ES256',
          typ: 'JWT',
          kid: 'key-1',
          jkt: 'thumbprint',
        })
      );
      const sig: Signature = {
        protected: headerB64,
        signature: 'sig',
      };

      const claims = getProtectedClaims(sig);
      expect(claims.alg).toBe('ES256');
      expect(claims.typ).toBe('JWT');
      expect(claims.kid).toBe('key-1');
      expect(claims.jkt).toBe('thumbprint');
    });
  });
});
