import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import test from "node:test";

test("SPIFFE production deploy builds only the SPIFFE workspace", () => {
  const deployScript = resolve(__dirname, "../../../scripts/deploy-production.mjs");
  const dryRun = execFileSync(process.execPath, [deployScript], {
    encoding: "utf8",
  });

  assert.match(dryRun, /pnpm --filter @agent-demo\/spiffe-mtls-agent build/);
  assert.doesNotMatch(dryRun, /(?:^|\n)pnpm build(?:\n|$)/);
  assert.doesNotMatch(dryRun, /agent-platform\/\.venv/);
});