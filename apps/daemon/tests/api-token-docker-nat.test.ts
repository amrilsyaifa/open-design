// Docker-NAT auth fix — OD_TRUST_PORT_BINDING path.
//
// In Docker the TCP peer of every browser request is the bridge gateway
// (e.g. 172.17.0.1) rather than 127.0.0.1, so the existing loopback bypass
// never fires.  The fix: docker-compose.yml sets OD_TRUST_PORT_BINDING=1 which
// tells the daemon that port-level access control is enforced by the container
// orchestration layer (the host-side port is bound to 127.0.0.1 only).  When
// OD_TRUST_PORT_BINDING=1 the daemon trusts ALL connections regardless of TCP
// peer address and does not install a bearer-token middleware.
//
// Security properties:
//   - The trust decision is explicit and operator-supplied, not inferred from
//     any HTTP header or cookie that a remote client could forge or mint.
//   - A remote attacker who reaches a publicly-bound daemon (i.e. operator
//     changed the port binding to 0.0.0.0) that still has OD_TRUST_PORT_BINDING=1
//     would have full access — this is intentional: the env var is a clear
//     statement that the operator trusts their own network boundary.
//   - The od-session cookie path has been removed entirely: no cookie is set on
//     HTML responses, and no cookie is accepted by the auth middleware. A remote
//     client that crafts an od-session cookie value is rejected with 401.
//   - Host headers are never trusted for auth bypass (Host is forgeable).

import type http from 'node:http';
import { networkInterfaces } from 'node:os';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { startServer } from '../src/server.js';

function getLanIp(): string | undefined {
  for (const ifaces of Object.values(networkInterfaces())) {
    for (const iface of ifaces ?? []) {
      if (!iface.internal && iface.family === 'IPv4') return iface.address;
    }
  }
}

const PREVIOUS_TOKEN         = process.env.OD_API_TOKEN;
const PREVIOUS_HOST          = process.env.OD_BIND_HOST;
const PREVIOUS_TRUST_BINDING = process.env.OD_TRUST_PORT_BINDING;

let server: http.Server | undefined;
let baseUrl = '';
let shutdown: (() => Promise<void> | void) | undefined;

afterEach(async () => {
  if (shutdown) await Promise.resolve(shutdown());
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  server = undefined;
  shutdown = undefined;
  if (PREVIOUS_TOKEN === undefined) delete process.env.OD_API_TOKEN;
  else process.env.OD_API_TOKEN = PREVIOUS_TOKEN;
  if (PREVIOUS_HOST === undefined) delete process.env.OD_BIND_HOST;
  else process.env.OD_BIND_HOST = PREVIOUS_HOST;
  if (PREVIOUS_TRUST_BINDING === undefined) delete process.env.OD_TRUST_PORT_BINDING;
  else process.env.OD_TRUST_PORT_BINDING = PREVIOUS_TRUST_BINDING;
});

describe('Host-spoofing regression guard', () => {
  it('isLoopbackBrowserRequest is no longer exported (Host-header bypass removed)', async () => {
    const serverModule = await import('../src/server.js');
    expect((serverModule as Record<string, unknown>).isLoopbackBrowserRequest).toBeUndefined();
  });

  it('loopback TCP peer still bypasses auth without any token (desktop / dev flow unchanged)', async () => {
    process.env.OD_API_TOKEN = 'test-loopback-token';
    const started = (await startServer({ port: 0, host: '127.0.0.1', returnServer: true })) as {
      url: string;
      server: http.Server;
      shutdown?: () => Promise<void> | void;
    };
    baseUrl = started.url;
    server = started.server;
    shutdown = started.shutdown;

    // 127.0.0.1 TCP peer → loopback bypass fires → 200 even with forged Host header
    const resp = await fetch(`${baseUrl}/api/plugins`, {
      headers: { Host: 'localhost:7456' },
    });
    expect(resp.status).toBe(200);
  });
});

describe('cookie regression', () => {
  it('GET / does not set an od-session cookie (cookie path removed)', async () => {
    // The previous (insecure) approach set an od-session cookie on every HTML
    // response, allowing any client that could reach GET / to mint a bearer-
    // equivalent credential. This test confirms the cookie is never issued.
    process.env.OD_API_TOKEN = 'cookie-regression-token';
    const started = (await startServer({ port: 0, host: '127.0.0.1', returnServer: true })) as {
      url: string;
      server: http.Server;
      shutdown?: () => Promise<void> | void;
    };
    server = started.server;
    shutdown = started.shutdown;
    baseUrl = started.url;

    const resp = await fetch(`${baseUrl}/`);
    // No od-session cookie must be set
    const setCookie = resp.headers.get('set-cookie') ?? '';
    expect(setCookie).not.toContain('od-session');
  });

  it('non-loopback peer with a crafted od-session cookie still gets 401', async () => {
    // This is the exact attack the previous cookie fix introduced:
    //   1. Remote client GET / (no auth) → old code would set Set-Cookie: od-session=<uuid>
    //   2. Remote client replays cookie on /api/* → old code granted access
    // With the cookie path removed, a crafted cookie is simply ignored.
    const lanIp = getLanIp();
    if (!lanIp) {
      console.log('    (skipped — no non-loopback interface found)');
      return;
    }

    const prev = process.env.OD_API_TOKEN;
    process.env.OD_API_TOKEN = 'cookie-replay-test-token';
    let srv: http.Server | undefined;
    let shut: (() => Promise<void> | void) | undefined;
    try {
      const started = (await startServer({ port: 0, host: '0.0.0.0', returnServer: true })) as {
        url: string;
        server: http.Server;
        shutdown?: () => Promise<void> | void;
      };
      srv = started.server;
      shut = started.shutdown;
      const port = (srv.address() as { port: number }).port;

      // Simulate: attacker crafts an od-session cookie and replays it
      const resp = await fetch(`http://${lanIp}:${port}/api/plugins`, {
        headers: { Cookie: 'od-session=attacker-crafted-value' },
      });
      expect(resp.status).toBe(401);
    } finally {
      if (shut) await Promise.resolve(shut());
      if (srv) await new Promise<void>((r) => srv!.close(() => r()));
      if (prev === undefined) delete process.env.OD_API_TOKEN;
      else process.env.OD_API_TOKEN = prev;
    }
  }, 30_000);
});

describe('OD_TRUST_PORT_BINDING', () => {
  it('allows daemon to start on 0.0.0.0 without OD_API_TOKEN', async () => {
    delete process.env.OD_API_TOKEN;
    process.env.OD_TRUST_PORT_BINDING = '1';
    const started = (await startServer({ port: 0, host: '0.0.0.0', returnServer: true })) as {
      url: string;
      server: http.Server;
      shutdown?: () => Promise<void> | void;
    };
    server = started.server;
    shutdown = started.shutdown;
    baseUrl = started.url;
    expect(baseUrl).toMatch(/^http:\/\//);
  });

  it('accepts all connections without a bearer token when active', async () => {
    delete process.env.OD_API_TOKEN;
    process.env.OD_TRUST_PORT_BINDING = '1';
    const started = (await startServer({ port: 0, host: '127.0.0.1', returnServer: true })) as {
      url: string;
      server: http.Server;
      shutdown?: () => Promise<void> | void;
    };
    server = started.server;
    shutdown = started.shutdown;
    baseUrl = started.url;

    const resp = await fetch(`${baseUrl}/api/plugins`);
    expect(resp.status).toBe(200);
  });
});
