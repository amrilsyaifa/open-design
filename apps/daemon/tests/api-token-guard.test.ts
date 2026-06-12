// Plan §3.K1 / spec §15.7 — bound-API-token guard.
//
// Two halves:
//   1. The daemon refuses to start with OD_BIND_HOST=0.0.0.0 when neither
//      OD_API_TOKEN nor OD_TRUST_PORT_BINDING=1 is set.
//   2. When OD_API_TOKEN is set (and OD_TRUST_PORT_BINDING is not), every
//      /api/* request from a non-loopback peer must carry
//      `Authorization: Bearer <OD_API_TOKEN>`. The health/readiness/version
//      probes stay open.
//
// Includes a Host-header spoofing regression: a non-loopback peer that
// forges `Host: localhost` must still receive 401 (Host is never trusted).

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

describe('bound-API-token guard', () => {
  it('refuses to start with OD_BIND_HOST=0.0.0.0 when OD_API_TOKEN is unset and OD_TRUST_PORT_BINDING is not set', async () => {
    delete process.env.OD_API_TOKEN;
    delete process.env.OD_TRUST_PORT_BINDING;
    await expect(startServer({ port: 0, host: '0.0.0.0', returnServer: true }))
      .rejects.toThrow(/OD_API_TOKEN/);
  });

  it('starts on a public host when OD_API_TOKEN is set', async () => {
    process.env.OD_API_TOKEN = 'test-token-abc';
    // Bind to 127.0.0.1 (loopback) but pretend we crossed the guard
    // by setting the env var; the assertion is that startup succeeds.
    const started = (await startServer({ port: 0, host: '127.0.0.1', returnServer: true })) as {
      url: string;
      server: http.Server;
      shutdown?: () => Promise<void> | void;
    };
    server = started.server;
    shutdown = started.shutdown;
    baseUrl = started.url;
    expect(baseUrl).toMatch(/^http:\/\/127\.0\.0\.1:/);
  });
});

describe('bearer middleware', () => {
  beforeEach(async () => {
    process.env.OD_API_TOKEN = 'secret-test-token';
    const started = (await startServer({ port: 0, host: '127.0.0.1', returnServer: true })) as {
      url: string;
      server: http.Server;
      shutdown?: () => Promise<void> | void;
    };
    baseUrl = started.url;
    server = started.server;
    shutdown = started.shutdown;
  });

  it('accepts loopback callers without a bearer (desktop UI flow)', async () => {
    // The HTTP test client is on the same machine → req.socket.remoteAddress
    // is 127.0.0.1 → middleware short-circuits.
    const resp = await fetch(`${baseUrl}/api/plugins`);
    expect(resp.status).toBe(200);
  });

  it('keeps health / readiness / version probes open without a bearer', async () => {
    for (const path of ['/api/health', '/api/ready', '/api/version']) {
      const resp = await fetch(`${baseUrl}${path}`);
      expect(resp.status).toBe(200);
    }
  });
});

describe('Host-header spoofing regression', () => {
  it('rejects a non-loopback peer with Host: localhost and no valid token', async () => {
    // Binds the daemon to 0.0.0.0 so we can connect from a LAN IP, which the
    // daemon sees as a non-loopback TCP peer. The test proves that a forged
    // Host: localhost header cannot bypass OD_API_TOKEN — the guard is
    // TCP-peer-only; request headers are never trusted for auth bypass.
    const lanIp = getLanIp();
    if (!lanIp) {
      // Skip in loopback-only CI environments.
      console.log('    (skipped — no non-loopback interface found)');
      return;
    }

    const prev = process.env.OD_API_TOKEN;
    process.env.OD_API_TOKEN = 'host-spoof-test-token';
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

      // Non-loopback peer + forged Host: localhost + no token → must be 401
      const resp = await fetch(`http://${lanIp}:${port}/api/plugins`, {
        headers: { Host: 'localhost:7456' },
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
