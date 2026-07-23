import assert from "node:assert/strict";
import test from "node:test";
import { StaticPeerPolicy } from "../src/policy/peer-policy";
import { assertSpiffeId } from "../src/spiffe/spiffe-id";

test("StaticPeerPolicy allows explicit source target action", () => {
  const sourceId = assertSpiffeId("spiffe://example.org/agent/coordinator");
  const targetId = assertSpiffeId("spiffe://example.org/agent/worker");
  const policy = new StaticPeerPolicy([
    {
      sourceId,
      targetIds: new Set([targetId]),
      actions: new Set(["agent:http"]),
    },
  ]);

  const decision = policy.authorize({ peerId: sourceId, targetId, action: "agent:http" });
  assert.equal(decision.allowed, true);
});

test("StaticPeerPolicy rejects missing source target action", () => {
  const sourceId = assertSpiffeId("spiffe://example.org/agent/coordinator");
  const targetId = assertSpiffeId("spiffe://example.org/agent/worker");
  const policy = new StaticPeerPolicy([]);

  assert.throws(() => policy.assertAuthorized({ peerId: sourceId, targetId, action: "agent:http" }), /not authorized/);
});