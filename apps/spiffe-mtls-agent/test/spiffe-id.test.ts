import assert from "node:assert/strict";
import test from "node:test";
import { assertSpiffeId, pathSegmentsFromSpiffeId, spiffeSetFromCsv, trustDomainFromSpiffeId } from "../src/spiffe/spiffe-id";

test("assertSpiffeId accepts a valid SPIFFE ID", () => {
  const spiffeId = assertSpiffeId("spiffe://example.org/agent/worker");
  assert.equal(trustDomainFromSpiffeId(spiffeId), "example.org");
  assert.deepEqual(pathSegmentsFromSpiffeId(spiffeId), ["agent", "worker"]);
});

test("assertSpiffeId rejects non-SPIFFE values", () => {
  assert.throws(() => assertSpiffeId("https://example.org/agent/worker"), /spiffe/);
  assert.throws(() => assertSpiffeId("spiffe://example.org/agent/worker?debug=true"), /must not include/);
});

test("spiffeSetFromCsv trims and validates allow-list entries", () => {
  const set = spiffeSetFromCsv(" spiffe://example.org/agent/a,spiffe://example.org/agent/b ");
  assert.equal(set.has("spiffe://example.org/agent/a"), true);
  assert.equal(set.has("spiffe://example.org/agent/b"), true);
});