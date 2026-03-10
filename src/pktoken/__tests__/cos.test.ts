import { parseCosignerClaims } from '../cos.js';

describe('Cosigner Claims', () => {
  const validClaims: Record<string, unknown> = {
    iss: 'https://cosigner.example.com',
    kid: 'key-1',
    alg: 'ES256',
    eid: 'event-123',
    auth_time: 1700000000,
    iat: 1700000000,
    exp: 1700003600,
    ruri: 'https://app.example.com/callback',
    nonce: 'nonce-abc123',
  };

  describe('parseCosignerClaims', () => {
    it('should parse valid cosigner claims', () => {
      const parsed = parseCosignerClaims(validClaims);

      expect(parsed.iss).toBe('https://cosigner.example.com');
      expect(parsed.kid).toBe('key-1');
      expect(parsed.alg).toBe('ES256');
      expect(parsed.eid).toBe('event-123');
      expect(parsed.auth_time).toBe(1700000000);
      expect(parsed.iat).toBe(1700000000);
      expect(parsed.exp).toBe(1700003600);
      expect(parsed.ruri).toBe('https://app.example.com/callback');
      expect(parsed.nonce).toBe('nonce-abc123');
    });

    it('should preserve optional typ claim', () => {
      const claimsWithTyp = { ...validClaims, typ: 'cos' };
      const parsed = parseCosignerClaims(claimsWithTyp);
      expect(parsed.typ).toBe('cos');
    });

    it('should handle undefined typ', () => {
      const parsed = parseCosignerClaims(validClaims);
      expect(parsed.typ).toBeUndefined();
    });

    it('should throw for missing iss', () => {
      const { iss: _iss, ...withoutIss } = validClaims;
      expect(() => parseCosignerClaims(withoutIss)).toThrow('missing required headers: iss');
    });

    it('should throw for missing kid', () => {
      const { kid: _kid, ...withoutKid } = validClaims;
      expect(() => parseCosignerClaims(withoutKid)).toThrow('missing required headers: kid');
    });

    it('should throw for missing alg', () => {
      const { alg: _alg, ...withoutAlg } = validClaims;
      expect(() => parseCosignerClaims(withoutAlg)).toThrow('missing required headers: alg');
    });

    it('should throw for missing eid', () => {
      const { eid: _eid, ...withoutEid } = validClaims;
      expect(() => parseCosignerClaims(withoutEid)).toThrow('missing required headers: eid');
    });

    it('should throw for missing auth_time', () => {
      const { auth_time: _authTime, ...withoutAuthTime } = validClaims;
      expect(() => parseCosignerClaims(withoutAuthTime)).toThrow(
        'missing required headers: auth_time'
      );
    });

    it('should throw for missing iat', () => {
      const { iat: _iat, ...withoutIat } = validClaims;
      expect(() => parseCosignerClaims(withoutIat)).toThrow('missing required headers: iat');
    });

    it('should throw for missing exp', () => {
      const { exp: _exp, ...withoutExp } = validClaims;
      expect(() => parseCosignerClaims(withoutExp)).toThrow('missing required headers: exp');
    });

    it('should throw for missing ruri', () => {
      const { ruri: _ruri, ...withoutRuri } = validClaims;
      expect(() => parseCosignerClaims(withoutRuri)).toThrow('missing required headers: ruri');
    });

    it('should throw for missing nonce', () => {
      const { nonce: _nonce, ...withoutNonce } = validClaims;
      expect(() => parseCosignerClaims(withoutNonce)).toThrow('missing required headers: nonce');
    });

    it('should throw for multiple missing fields', () => {
      const { iss: _iss, kid: _kid, alg: _alg, ...withoutMultiple } = validClaims;
      expect(() => parseCosignerClaims(withoutMultiple)).toThrow('iss, kid, alg');
    });

    it('should throw for empty object', () => {
      expect(() => parseCosignerClaims({})).toThrow('missing required headers');
    });
  });
});
