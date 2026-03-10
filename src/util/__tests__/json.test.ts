import { jsonStringifySorted } from '../json.js';

describe('JSON Utils', () => {
  describe('jsonStringifySorted', () => {
    it('should sort object keys alphabetically', () => {
      const obj = { z: 1, a: 2, m: 3 };
      expect(jsonStringifySorted(obj)).toBe('{"a":2,"m":3,"z":1}');
    });

    it('should handle nested objects', () => {
      const obj = { b: { z: 1, a: 2 }, a: 1 };
      expect(jsonStringifySorted(obj)).toBe('{"a":1,"b":{"a":2,"z":1}}');
    });

    it('should handle arrays', () => {
      const arr = [3, 1, 2];
      expect(jsonStringifySorted(arr)).toBe('[3,1,2]');
    });

    it('should handle arrays with objects', () => {
      const arr = [{ b: 1, a: 2 }];
      expect(jsonStringifySorted(arr)).toBe('[{"a":2,"b":1}]');
    });

    it('should handle null', () => {
      expect(jsonStringifySorted(null)).toBe('null');
    });

    it('should handle primitives', () => {
      expect(jsonStringifySorted('hello')).toBe('"hello"');
      expect(jsonStringifySorted(42)).toBe('42');
      expect(jsonStringifySorted(true)).toBe('true');
    });

    it('should handle empty object', () => {
      expect(jsonStringifySorted({})).toBe('{}');
    });

    it('should handle empty array', () => {
      expect(jsonStringifySorted([])).toBe('[]');
    });

    it('should match Go json.Marshal key ordering', () => {
      // This is the critical test - Go always sorts keys
      const jwk = {
        kty: 'EC',
        crv: 'P-256',
        x: 'base64x',
        y: 'base64y',
        alg: 'ES256',
      };
      const result = jsonStringifySorted(jwk);
      expect(result).toBe('{"alg":"ES256","crv":"P-256","kty":"EC","x":"base64x","y":"base64y"}');
    });
  });
});
