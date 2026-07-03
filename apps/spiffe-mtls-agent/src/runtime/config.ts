import { SpiffeConfigurationError } from "../errors";
import { assertSpiffeId, spiffeSetFromCsv, type SpiffeId } from "../spiffe/spiffe-id";

export type AgentRuntimeConfig = {
  spiffeEndpointSocket: string;
  agentSpiffeId: SpiffeId;
  host: string;
  port: number;
  allowedClientIds: ReadonlySet<SpiffeId>;
};

export type AgentClientRuntimeConfig = {
  spiffeEndpointSocket: string;
  agentSpiffeId: SpiffeId;
  targetAgentUrl: URL;
  targetAgentSpiffeId: SpiffeId;
};

export function requiredEnv(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (!value) throw new SpiffeConfigurationError(`Missing required environment variable ${name}`);
  return value;
}

export function loadServerConfig(env: NodeJS.ProcessEnv = process.env): AgentRuntimeConfig {
  return {
    spiffeEndpointSocket: requiredEnv(env, "SPIFFE_ENDPOINT_SOCKET"),
    agentSpiffeId: assertSpiffeId(requiredEnv(env, "AGENT_SPIFFE_ID"), "AGENT_SPIFFE_ID"),
    host: env.HOST ?? "0.0.0.0",
    port: Number.parseInt(env.PORT ?? "8443", 10),
    allowedClientIds: spiffeSetFromCsv(requiredEnv(env, "ALLOWED_CLIENT_SPIFFE_IDS")),
  };
}

export function loadClientConfig(env: NodeJS.ProcessEnv = process.env): AgentClientRuntimeConfig {
  return {
    spiffeEndpointSocket: requiredEnv(env, "SPIFFE_ENDPOINT_SOCKET"),
    agentSpiffeId: assertSpiffeId(requiredEnv(env, "AGENT_SPIFFE_ID"), "AGENT_SPIFFE_ID"),
    targetAgentUrl: new URL(requiredEnv(env, "TARGET_AGENT_URL")),
    targetAgentSpiffeId: assertSpiffeId(requiredEnv(env, "TARGET_AGENT_SPIFFE_ID"), "TARGET_AGENT_SPIFFE_ID"),
  };
}