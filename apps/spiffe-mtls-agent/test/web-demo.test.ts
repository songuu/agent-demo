import assert from "node:assert/strict";
import { once } from "node:events";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { getDemoSnapshot } from "../src/web/demo-model";
import { renderDemoPage } from "../src/web/demo-page";
import { createDemoHttpServer } from "../src/web/demo-server";

async function listenOnEphemeralPort(server: Server): Promise<number> {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.notEqual(typeof address, "string");
  assert.ok(address);
  return (address as AddressInfo).port;
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
}

test("demo snapshot covers the complete SPIFFE mTLS flow", () => {
  const snapshot = getDemoSnapshot("127.0.0.1", 5173, "/agent-demo/spiffe");

  assert.equal(snapshot.commands.web, "pnpm demo:spiffe");
  assert.equal(snapshot.basePath, "/agent-demo/spiffe");
  assert.equal(snapshot.trustDomain, "example.org");
  assert.equal(snapshot.steps.length, 8);
  assert.ok(snapshot.steps.some((step) => step.id === "client-checks-server"));
  assert.ok(snapshot.steps.some((step) => step.id === "authorize" && step.layer === "policy"));
  assert.ok(snapshot.failureScenarios.some((scenario) => scenario.id === "server-id-mismatch"));
  assert.ok(snapshot.failureScenarios.some((scenario) => scenario.id === "policy-deny"));
});

test("demo page embeds the interactive model with base-path-safe assets", () => {
  const html = renderDemoPage(getDemoSnapshot("127.0.0.1", 5173, "/agent-demo/spiffe"));

  assert.match(html, /SPIFFE mTLS Agent 过程演示/);
  assert.match(html, /window\.__DEMO__/);
  assert.match(html, /播放成功路径/);
  assert.match(html, /\/agent-demo\/spiffe\/assets\/spiffe-agent-mtls-complete-architecture\.svg/);
});

test("demo server serves page, API, health check, and architecture asset", async () => {
  const server = createDemoHttpServer({ host: "127.0.0.1", port: 0 });
  const port = await listenOnEphemeralPort(server);

  try {
    const page = await fetch(`http://127.0.0.1:${port}/`);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /SPIFFE mTLS Agent 过程演示/);

    const api = await fetch(`http://127.0.0.1:${port}/api/demo`);
    assert.equal(api.status, 200);
    const body = (await api.json()) as { ok: boolean; demo: { steps: unknown[] } };
    assert.equal(body.ok, true);
    assert.equal(body.demo.steps.length, 8);

    const health = await fetch(`http://127.0.0.1:${port}/healthz`);
    assert.equal(health.status, 200);
    assert.equal((await health.json() as { ok: boolean }).ok, true);

    const asset = await fetch(`http://127.0.0.1:${port}/assets/spiffe-agent-mtls-complete-architecture.svg`);
    assert.equal(asset.status, 200);
    assert.match(asset.headers.get("content-type") ?? "", /image\/svg\+xml/);

    const head = await fetch(`http://127.0.0.1:${port}/assets/spiffe-agent-mtls-complete-architecture.svg`, { method: "HEAD" });
    assert.equal(head.status, 200);
  } finally {
    await closeServer(server);
  }
});

test("demo server can mount under a future multi-app base path", async () => {
  const server = createDemoHttpServer({ host: "127.0.0.1", port: 0, basePath: "/agent-demo/spiffe" });
  const port = await listenOnEphemeralPort(server);

  try {
    const page = await fetch(`http://127.0.0.1:${port}/agent-demo/spiffe/`);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.match(html, /\/agent-demo\/spiffe\/assets\/spiffe-agent-mtls-complete-architecture\.svg/);

    const api = await fetch(`http://127.0.0.1:${port}/agent-demo/spiffe/api/demo`);
    assert.equal(api.status, 200);
    const body = (await api.json()) as { ok: boolean; demo: { basePath: string } };
    assert.equal(body.ok, true);
    assert.equal(body.demo.basePath, "/agent-demo/spiffe");

    const health = await fetch(`http://127.0.0.1:${port}/agent-demo/spiffe/healthz`);
    assert.equal(health.status, 200);

    const asset = await fetch(`http://127.0.0.1:${port}/agent-demo/spiffe/assets/spiffe-agent-mtls-complete-architecture.svg`);
    assert.equal(asset.status, 200);
  } finally {
    await closeServer(server);
  }
});