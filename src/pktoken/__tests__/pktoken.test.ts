import { PKToken } from '../pktoken.js';

describe('PKToken', () => {
  describe('constructor', () => {
    it('should create an empty PKToken', () => {
      const pkt = new PKToken();
      expect(pkt).toBeDefined();
      expect(pkt.payload).toBeDefined();
      expect(pkt.payload.length).toBe(0);
    });
  });

  describe('identityString', () => {
    it('should return subject and issuer', () => {
      const pkt = new PKToken();
      const payload = JSON.stringify({
        sub: 'user123',
        iss: 'https://example.com',
        aud: 'client-id',
      });
      pkt.payload = new TextEncoder().encode(payload);

      const identity = pkt.identityString();
      expect(identity).toBe('user123 https://example.com');
    });
  });

  describe('issuer', () => {
    it('should extract issuer from payload', () => {
      const pkt = new PKToken();
      const payload = JSON.stringify({
        sub: 'user123',
        iss: 'https://accounts.google.com',
        aud: 'client-id',
      });
      pkt.payload = new TextEncoder().encode(payload);

      const issuer = pkt.issuer();
      expect(issuer).toBe('https://accounts.google.com');
    });

    it('should throw error if issuer missing', () => {
      const pkt = new PKToken();
      const payload = JSON.stringify({
        sub: 'user123',
        aud: 'client-id',
      });
      pkt.payload = new TextEncoder().encode(payload);

      expect(() => pkt.issuer()).toThrow('missing iss');
    });
  });

  describe('subject', () => {
    it('should extract subject from payload', () => {
      const pkt = new PKToken();
      const payload = JSON.stringify({
        sub: 'user123',
        iss: 'https://example.com',
        aud: 'client-id',
      });
      pkt.payload = new TextEncoder().encode(payload);

      const subject = pkt.subject();
      expect(subject).toBe('user123');
    });
  });

  describe('audience', () => {
    it('should extract audience from payload', () => {
      const pkt = new PKToken();
      const payload = JSON.stringify({
        sub: 'user123',
        iss: 'https://example.com',
        aud: 'my-client-id',
      });
      pkt.payload = new TextEncoder().encode(payload);

      const audience = pkt.audience();
      expect(audience).toBe('my-client-id');
    });
  });
});
