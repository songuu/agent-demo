import { runClientFromEnv, runServerFromEnv } from "./runtime/run-agent";

export async function main(argv = process.argv.slice(2), env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const mode = argv[0];

  if (mode === "server") {
    await runServerFromEnv(env);
    return;
  }

  if (mode === "client") {
    await runClientFromEnv(env);
    return;
  }

  console.error(`Usage:
  SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock \\
  AGENT_SPIFFE_ID=spiffe://example.org/agent/worker \\
  ALLOWED_CLIENT_SPIFFE_IDS=spiffe://example.org/agent/coordinator \\
  PORT=8443 pnpm start:server

  SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock \\
  AGENT_SPIFFE_ID=spiffe://example.org/agent/coordinator \\
  TARGET_AGENT_URL=https://worker.agents.svc:8443/ \\
  TARGET_AGENT_SPIFFE_ID=spiffe://example.org/agent/worker \\
  pnpm start:client`);
  process.exitCode = 2;
}