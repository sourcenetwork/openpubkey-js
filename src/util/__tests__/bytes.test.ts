import { joinBytes, joinJWTSegments, concatBytes, bytesEqual } from '../bytes.js';

describe('Bytes Utils', () => {
  describe('joinBytes', () => {
    it('should join byte arrays with separator', () => {
      const a = new Uint8Array([1, 2]);
      const b = new Uint8Array([3, 4]);
      const result = joinBytes(0, a, b);
      expect(result).toEqual(new Uint8Array([1, 2, 0, 3, 4]));
    });

    it('should handle single array', () => {
      const a = new Uint8Array([1, 2, 3]);
      const result = joinBytes(0, a);
      expect(result).toEqual(new Uint8Array([1, 2, 3]));
    });

    it('should handle empty arrays', () => {
      const a = new Uint8Array([]);
      const b = new Uint8Array([]);
      const result = joinBytes(0, a, b);
      expect(result).toEqual(new Uint8Array([0]));
    });

    it('should handle multiple arrays', () => {
      const a = new Uint8Array([1]);
      const b = new Uint8Array([2]);
      const c = new Uint8Array([3]);
      const result = joinBytes(255, a, b, c);
      expect(result).toEqual(new Uint8Array([1, 255, 2, 255, 3]));
    });
  });

  describe('joinJWTSegments', () => {
    it('should join segments with period separator', () => {
      const header = new TextEncoder().encode('header');
      const payload = new TextEncoder().encode('payload');
      const sig = new TextEncoder().encode('sig');
      const result = joinJWTSegments(header, payload, sig);
      expect(new TextDecoder().decode(result)).toBe('header.payload.sig');
    });
  });

  describe('concatBytes', () => {
    it('should concatenate byte arrays', () => {
      const a = new Uint8Array([1, 2]);
      const b = new Uint8Array([3, 4]);
      const result = concatBytes(a, b);
      expect(result).toEqual(new Uint8Array([1, 2, 3, 4]));
    });

    it('should handle empty arrays', () => {
      const a = new Uint8Array([1, 2]);
      const b = new Uint8Array([]);
      const result = concatBytes(a, b);
      expect(result).toEqual(new Uint8Array([1, 2]));
    });

    it('should handle multiple arrays', () => {
      const a = new Uint8Array([1]);
      const b = new Uint8Array([2]);
      const c = new Uint8Array([3]);
      const result = concatBytes(a, b, c);
      expect(result).toEqual(new Uint8Array([1, 2, 3]));
    });

    it('should handle no arrays', () => {
      const result = concatBytes();
      expect(result).toEqual(new Uint8Array([]));
    });
  });

  describe('bytesEqual', () => {
    it('should return true for equal arrays', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 3]);
      expect(bytesEqual(a, b)).toBe(true);
    });

    it('should return false for different lengths', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2]);
      expect(bytesEqual(a, b)).toBe(false);
    });

    it('should return false for different values', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 4]);
      expect(bytesEqual(a, b)).toBe(false);
    });

    it('should return true for empty arrays', () => {
      const a = new Uint8Array([]);
      const b = new Uint8Array([]);
      expect(bytesEqual(a, b)).toBe(true);
    });
  });
});
