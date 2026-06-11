// Tests for isLoopbackBrowserRequest — the fallback loopback bypass used when
// Docker NAT changes the TCP peer address from 127.0.0.1 to the bridge
// gateway (e.g. 172.17.0.1).  Because unit tests always run with a loopback
// TCP peer, the peer-address check fires first and prevents us from testing
// the new helper through the live HTTP layer.  We test the function directly
// instead, covering every branch with minimal mock request objects.

import { describe, expect, it } from 'vitest';
import { isLoopbackBrowserRequest } from '../src/server.js';

function req(host: string, origin?: string): { get(name: string): string | undefined } {
  return {
    get(name: string) {
      if (name === 'host') return host;
      if (name === 'origin') return origin;
      return undefined;
    },
  };
}

describe('isLoopbackBrowserRequest', () => {
  describe('loopback Host, no Origin — Docker browser pattern', () => {
    it('accepts localhost:<port>', () => {
      expect(isLoopbackBrowserRequest(req('localhost:7456'))).toBe(true);
    });

    it('accepts 127.0.0.1:<port>', () => {
      expect(isLoopbackBrowserRequest(req('127.0.0.1:7456'))).toBe(true);
    });

    it('accepts [::1]:<port>', () => {
      expect(isLoopbackBrowserRequest(req('[::1]:7456'))).toBe(true);
    });
  });

  describe('loopback Host + loopback Origin', () => {
    it('accepts matching loopback origin', () => {
      expect(isLoopbackBrowserRequest(req('127.0.0.1:7456', 'http://127.0.0.1:7456'))).toBe(true);
    });

    it('accepts localhost origin', () => {
      expect(isLoopbackBrowserRequest(req('localhost:7456', 'http://localhost:7456'))).toBe(true);
    });
  });

  describe('security: loopback Host + non-loopback Origin — DNS-rebinding / OD_ALLOWED_ORIGINS guard', () => {
    it('rejects external domain origin', () => {
      expect(isLoopbackBrowserRequest(req('localhost:7456', 'https://evil.com'))).toBe(false);
    });

    it('rejects OD_ALLOWED_ORIGINS-style external origin', () => {
      expect(isLoopbackBrowserRequest(req('127.0.0.1:7456', 'https://od.example.com'))).toBe(false);
    });

    it('rejects malformed origin', () => {
      expect(isLoopbackBrowserRequest(req('localhost:7456', 'not-a-url'))).toBe(false);
    });
  });

  describe('non-loopback Host — reverse proxy or public interface', () => {
    it('rejects external hostname regardless of origin', () => {
      expect(isLoopbackBrowserRequest(req('od.example.com:443'))).toBe(false);
    });

    it('rejects IP on a public interface', () => {
      expect(isLoopbackBrowserRequest(req('203.0.113.10:7456'))).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('handles missing host header', () => {
      expect(isLoopbackBrowserRequest(req(''))).toBe(false);
    });
  });
});
