import { base64EncodeForJWT, base64DecodeForJWT } from '../base64.js';

describe('Base64 Utils', () => {
  describe('base64EncodeForJWT', () => {
    it('should encode bytes to base64url', () => {
      const input = new TextEncoder().encode('Hello, World!');
      const encoded = base64EncodeForJWT(input);
      const encodedStr = new TextDecoder().decode(encoded);

      // Should be base64url without padding
      expect(encodedStr).not.toContain('=');
      expect(encodedStr).not.toContain('+');
      expect(encodedStr).not.toContain('/');
    });

    it('should handle empty input', () => {
      const input = new Uint8Array(0);
      const encoded = base64EncodeForJWT(input);
      expect(encoded.length).toBe(0);
    });
  });

  describe('base64DecodeForJWT', () => {
    it('should decode base64url to bytes', () => {
      const input = new TextEncoder().encode('Hello, World!');
      const encoded = base64EncodeForJWT(input);
      const decoded = base64DecodeForJWT(encoded);

      expect(decoded).toEqual(input);
    });

    it('should round trip correctly', () => {
      const testCases = [
        'Hello, World!',
        'The quick brown fox',
        '{"sub":"user123","iss":"https://example.com"}',
        '',
      ];

      for (const testCase of testCases) {
        const input = new TextEncoder().encode(testCase);
        const encoded = base64EncodeForJWT(input);
        const decoded = base64DecodeForJWT(encoded);
        const result = new TextDecoder().decode(decoded);

        expect(result).toBe(testCase);
      }
    });
  });
});
