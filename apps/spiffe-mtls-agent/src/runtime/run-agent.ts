import { allowListedClientsPolicy } from "../policy/peer-policy";
import { WorkloadApiX509Source } from "../spiffe/workload-x509-source";
import { SpiffeMtlsAgentClient } from "../transport/spiffe-http-client";
import { SpiffeMtlsAgentServer } from "../transport/spiffe-http-server";
import { loadClientConfig, loadServerConfig } from "./config";

export async function runServerFromEnv(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const config = loadServerConfig(env);
  const source = new WorkloadApiX509Source();
  await source.start({
    spiffeEndpointSocket: config.spiffeEndpointSocket,
    spiffeId: config.agentSpiffeId,
  });

  const server = new SpiffeMtlsAgentServer(source, allowListedClientsPolicy(config.allowedClientIds));
  await server.listen(config.port, config.host);

  console.log(
    JSON.stringify({
      ok: true,
      mode: "server",
      spiffeId: source.required().spiffeId,
      port: config.port,
      expiresAt: source.required().expiresAt?.toISOString(),
    }),
  );
}

export async function runClientFromEnv(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const config = loadClientConfig(env);
  const source = new WorkloadApiX509Source();
  await source.start({
    spiffeEndpointSocket: config.spiffeEndpointSocket,
    spiffeId: config.agentSpiffeId,
  });

  const client = new SpiffeMtlsAgentClient(source);
  const response = await client.requestJson(config.targetAgentUrl, config.targetAgentSpiffeId);

  console.log(JSON.stringify(response, null, 2));
  source.stop();
}