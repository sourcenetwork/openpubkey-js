import { compactPKToken, splitCompactPKToken } from '../compact.js';

describe('PK Token Compact Format', () => {
  // Create mock JWT-like tokens with same payload
  const createMockToken = (header: string, sig: string): Uint8Array => {
    const payload = 'eyJzdWIiOiJ1c2VyMTIzIn0'; // {"sub":"user123"} base64url
    return new TextEncoder().encode(`${header}.${payload}.${sig}`);
  };

  describe('compactPKToken', () => {
    it('should compact a single token', () => {
      const token = createMockToken('header1', 'sig1');
      const compact = compactPKToken([token]);
      const compactStr = new TextDecoder().decode(compact);

      // Format: payload:header1:sig1
      expect(compactStr).toBe('eyJzdWIiOiJ1c2VyMTIzIn0:header1:sig1');
    });

    it('should compact multiple tokens with same payload', () => {
      const token1 = createMockToken('header1', 'sig1');
      const token2 = createMockToken('header2', 'sig2');
      const compact = compactPKToken([token1, token2]);
      const compactStr = new TextDecoder().decode(compact);

      // Format: payload:header1:sig1:header2:sig2
      expect(compactStr).toBe('eyJzdWIiOiJ1c2VyMTIzIn0:header1:sig1:header2:sig2');
    });

    it('should throw for empty tokens array', () => {
      expect(() => compactPKToken([])).toThrow('No tokens provided');
    });

    it('should throw for tokens with different payloads', () => {
      const token1 = new TextEncoder().encode('header1.payload1.sig1');
      const token2 = new TextEncoder().encode('header2.payload2.sig2');
      expect(() => compactPKToken([token1, token2])).toThrow('Payloads in tokens are not the same');
    });

    it('should include fresh ID token when provided', () => {
      const token = createMockToken('header1', 'sig1');
      const freshToken = new TextEncoder().encode('fresh.id.token');
      const compact = compactPKToken([token], freshToken);
      const compactStr = new TextDecoder().decode(compact);

      expect(compactStr).toBe('eyJzdWIiOiJ1c2VyMTIzIn0:header1:sig1.fresh.id.token');
    });

    it('should throw for invalid fresh ID token format', () => {
      const token = createMockToken('header1', 'sig1');
      const invalidFresh = new TextEncoder().encode('invalid-format');
      expect(() => compactPKToken([token], invalidFresh)).toThrow('Invalid refreshed ID Token');
    });
  });

  describe('splitCompactPKToken', () => {
    it('should split a compacted single token', () => {
      const compact = new TextEncoder().encode('payload:header1:sig1');
      const [tokens, fresh] = splitCompactPKToken(compact);

      expect(tokens.length).toBe(1);
      expect(new TextDecoder().decode(tokens[0])).toBe('header1.payload.sig1');
      expect(fresh).toBeNull();
    });

    it('should split compacted multiple tokens', () => {
      const compact = new TextEncoder().encode('payload:header1:sig1:header2:sig2');
      const [tokens, fresh] = splitCompactPKToken(compact);

      expect(tokens.length).toBe(2);
      expect(new TextDecoder().decode(tokens[0])).toBe('header1.payload.sig1');
      expect(new TextDecoder().decode(tokens[1])).toBe('header2.payload.sig2');
      expect(fresh).toBeNull();
    });

    it('should extract fresh ID token', () => {
      const compact = new TextEncoder().encode('payload:header1:sig1.fresh.id.token');
      const [tokens, fresh] = splitCompactPKToken(compact);

      expect(tokens.length).toBe(1);
      expect(fresh).not.toBeNull();
      expect(new TextDecoder().decode(fresh!)).toBe('fresh.id.token');
    });

    it('should throw for invalid segment count', () => {
      const invalid1 = new TextEncoder().encode('payload:header');
      expect(() => splitCompactPKToken(invalid1)).toThrow('Invalid number of segments');

      const invalid2 = new TextEncoder().encode('payload:header:sig:extra');
      expect(() => splitCompactPKToken(invalid2)).toThrow('Invalid number of segments');
    });

    it('should throw for invalid fresh ID token in split', () => {
      const compact = new TextEncoder().encode('payload:header1:sig1.invalid');
      expect(() => splitCompactPKToken(compact)).toThrow('Invalid refreshed ID Token');
    });
  });

  describe('round-trip', () => {
    it('should round-trip single token', () => {
      const original = createMockToken('header1', 'sig1');
      const compact = compactPKToken([original]);
      const [tokens] = splitCompactPKToken(compact);

      expect(tokens.length).toBe(1);
      expect(tokens[0]).toEqual(original);
    });

    it('should round-trip multiple tokens', () => {
      const token1 = createMockToken('header1', 'sig1');
      const token2 = createMockToken('header2', 'sig2');
      const compact = compactPKToken([token1, token2]);
      const [tokens] = splitCompactPKToken(compact);

      expect(tokens.length).toBe(2);
      expect(tokens[0]).toEqual(token1);
      expect(tokens[1]).toEqual(token2);
    });

    it('should round-trip with fresh token', () => {
      const token = createMockToken('header1', 'sig1');
      const freshToken = new TextEncoder().encode('fresh.id.token');
      const compact = compactPKToken([token], freshToken);
      const [tokens, fresh] = splitCompactPKToken(compact);

      expect(tokens.length).toBe(1);
      expect(tokens[0]).toEqual(token);
      expect(fresh).toEqual(freshToken);
    });
  });
});
