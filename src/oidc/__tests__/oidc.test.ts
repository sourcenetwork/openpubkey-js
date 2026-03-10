import { splitCompact, parseJWTSegment, parseOidcClaims } from '../oidc.js';
import { base64UrlEncode } from '../../util/base64.js';

describe('OIDC Utils', () => {
  describe('splitCompact', () => {
    it('should split a JWT string into three parts', () => {
      const jwt = 'header.payload.signature';
      const [header, payload, sig] = splitCompact(jwt);
      expect(new TextDecoder().decode(header)).toBe('header');
      expect(new TextDecoder().decode(payload)).toBe('payload');
      expect(new TextDecoder().decode(sig)).toBe('signature');
    });

    it('should split a JWT Uint8Array into three parts', () => {
      const jwt = new TextEncoder().encode('header.payload.signature');
      const [header, payload, sig] = splitCompact(jwt);
      expect(new TextDecoder().decode(header)).toBe('header');
      expect(new TextDecoder().decode(payload)).toBe('payload');
      expect(new TextDecoder().decode(sig)).toBe('signature');
    });

    it('should throw for invalid JWT with wrong number of parts', () => {
      expect(() => splitCompact('header.payload')).toThrow('Invalid number of segments');
      expect(() => splitCompact('header')).toThrow('Invalid number of segments');
      expect(() => splitCompact('a.b.c.d')).toThrow('Invalid number of segments');
    });
  });

  describe('parseJWTSegment', () => {
    it('should parse a base64url encoded JSON segment', () => {
      const obj = { foo: 'bar', num: 42 };
      const encoded = base64UrlEncode(JSON.stringify(obj));
      const result = parseJWTSegment(encoded);
      expect(result).toEqual(obj);
    });

    it('should parse segment from Uint8Array', () => {
      const obj = { test: true };
      const encoded = new TextEncoder().encode(base64UrlEncode(JSON.stringify(obj)));
      const result = parseJWTSegment(encoded);
      expect(result).toEqual(obj);
    });
  });

  describe('parseOidcClaims', () => {
    it('should parse standard OIDC claims', () => {
      const data = {
        iss: 'https://accounts.google.com',
        sub: 'user123',
        aud: 'client-id',
        exp: 1234567890,
        iat: 1234567800,
        email: 'user@example.com',
        nonce: 'abc123',
      };
      const claims = parseOidcClaims(data);
      expect(claims.iss).toBe('https://accounts.google.com');
      expect(claims.sub).toBe('user123');
      expect(claims.aud).toBe('client-id');
      expect(claims.exp).toBe(1234567890);
      expect(claims.iat).toBe(1234567800);
      expect(claims.email).toBe('user@example.com');
      expect(claims.nonce).toBe('abc123');
    });

    it('should preserve audience as array when provided as array', () => {
      const data = {
        iss: 'https://example.com',
        sub: 'user',
        aud: ['client1', 'client2'],
        exp: 1234567890,
        iat: 1234567800,
      };
      const claims = parseOidcClaims(data);
      expect(Array.isArray(claims.aud)).toBe(true);
      expect(claims.aud).toEqual(['client1', 'client2']);
    });

    it('should handle optional fields', () => {
      const data = {
        iss: 'https://example.com',
        sub: 'user',
        aud: 'client',
        exp: 1234567890,
        iat: 1234567800,
      };
      const claims = parseOidcClaims(data);
      expect(claims.email).toBeUndefined();
      expect(claims.nonce).toBeUndefined();
      expect(claims.preferred_username).toBeUndefined();
      expect(claims.groups).toBeUndefined();
    });

    it('should parse groups and scopes arrays', () => {
      const data = {
        iss: 'https://example.com',
        sub: 'user',
        aud: 'client',
        exp: 1234567890,
        iat: 1234567800,
        groups: ['admin', 'users'],
        scopes: ['read', 'write'],
      };
      const claims = parseOidcClaims(data);
      expect(claims.groups).toEqual(['admin', 'users']);
      expect(claims.scopes).toEqual(['read', 'write']);
    });
  });
});
