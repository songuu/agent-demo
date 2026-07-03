export type DemoActor = {
  id: string;
  title: string;
  subtitle: string;
  spiffeId?: string;
};

export type DemoLayer = "trust" | "identity" | "transport" | "policy" | "runtime" | "observe";

export type DemoStep = {
  id: string;
  index: number;
  layer: DemoLayer;
  actor: string;
  title: string;
  shortTitle: string;
  description: string;
  evidence: string;
  codeRefs: string[];
  log: string;
};

export type FailureScenario = {
  id: string;
  title: string;
  trigger: string;
  expectedResult: string;
  blockedAtStepId: string;
};

export type ArchitectureLayer = {
  id: DemoLayer;
  title: string;
  purpose: string;
  files: string[];
};

export type DemoSnapshot = {
  title: string;
  subtitle: string;
  localUrl: string;
  basePath: string;
  trustDomain: string;
  actors: DemoActor[];
  layers: ArchitectureLayer[];
  steps: DemoStep[];
  failureScenarios: FailureScenario[];
  commands: {
    install: string;
    web: string;
    server: string;
    client: string;
  };
  auditEvents: Array<Record<string, string>>;
};

export const demoActors: DemoActor[] = [
  {
    id: "spire-server",
    title: "SPIRE Server",
    subtitle: "Workload entry, issuer, trust bundle",
  },
  {
    id: "spire-agent",
    title: "SPIRE Agent",
    subtitle: "Node-local Workload API socket",
  },
  {
    id: "coordinator",
    title: "Agent A: coordinator",
    subtitle: "Client side caller",
    spiffeId: "spiffe://example.org/agent/coordinator",
  },
  {
    id: "worker",
    title: "Agent B: worker",
    subtitle: "Server side target",
    spiffeId: "spiffe://example.org/agent/worker",
  },
  {
    id: "policy",
    title: "PeerPolicy",
    subtitle: "caller / target / action authorization",
  },
  {
    id: "audit",
    title: "Audit Log",
    subtitle: "localSpiffeId, peerSpiffeId, action, decision",
  },
];

export const architectureLayers: ArchitectureLayer[] = [
  {
    id: "trust",
    title: "Trust Plane",
    purpose: "决定哪个 workload 能拿哪个 SPIFFE ID，并发布验证证书链用的 trust bundle。",
    files: ["deploy/spire/registration-entries.md", "config/agent-policy.example.json"],
  },
  {
    id: "identity",
    title: "Identity Layer",
    purpose: "通过 Workload API 获取短期 X.509-SVID、private key 和 bundle，并处理轮换。",
    files: ["src/spiffe/workload-x509-source.ts", "src/spiffe/peer-certificate.ts"],
  },
  {
    id: "transport",
    title: "mTLS Transport",
    purpose: "Client 校验 server SPIFFE ID；Server 要求 client cert 并提取 caller SPIFFE ID。",
    files: ["src/transport/spiffe-http-client.ts", "src/transport/spiffe-http-server.ts"],
  },
  {
    id: "policy",
    title: "Authorization",
    purpose: "TLS 只证明身份，Policy 决定 caller 能不能访问 target/action。",
    files: ["src/policy/peer-policy.ts"],
  },
  {
    id: "runtime",
    title: "Runtime",
    purpose: "把环境变量组装成可运行 server/client，并暴露页面 demo 服务。",
    files: ["src/runtime/run-agent.ts", "src/web/demo-server.ts"],
  },
  {
    id: "observe",
    title: "Observability",
    purpose: "记录安全可审计字段，不记录 private key 或完整证书。",
    files: ["docs/runbooks/spire-runtime-checklist.md"],
  },
];

export const demoSteps: DemoStep[] = [
  {
    id: "register",
    index: 1,
    layer: "trust",
    actor: "SPIRE Server",
    title: "注册 workload identity",
    shortTitle: "Register",
    description: "SPIRE Server 根据 workload entry 和 selector，声明 coordinator / worker 可以拿到各自的 SPIFFE ID。",
    evidence: "coordinator -> spiffe://example.org/agent/coordinator；worker -> spiffe://example.org/agent/worker",
    codeRefs: ["deploy/spire/registration-entries.md", "config/agent-policy.example.json"],
    log: "registration entries loaded for coordinator and worker",
  },
  {
    id: "fetch-client-svid",
    index: 2,
    layer: "identity",
    actor: "Agent A",
    title: "Client 获取自己的 X.509-SVID",
    shortTitle: "Client SVID",
    description: "Coordinator 连接本机 Workload API socket，拿到短期 cert/key 和 trust bundle。",
    evidence: "SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock",
    codeRefs: ["src/spiffe/workload-x509-source.ts", "src/runtime/config.ts"],
    log: "client material ready: spiffe://example.org/agent/coordinator",
  },
  {
    id: "fetch-server-svid",
    index: 3,
    layer: "identity",
    actor: "Agent B",
    title: "Server 获取自己的 X.509-SVID",
    shortTitle: "Server SVID",
    description: "Worker 同样从 Workload API 获取短期身份材料，并用它创建 HTTPS server secure context。",
    evidence: "requestCert=true, rejectUnauthorized=true, minVersion=TLSv1.2",
    codeRefs: ["src/transport/spiffe-http-server.ts", "src/spiffe/workload-x509-source.ts"],
    log: "server material ready: spiffe://example.org/agent/worker",
  },
  {
    id: "client-checks-server",
    index: 4,
    layer: "transport",
    actor: "Agent A -> Agent B",
    title: "Client 校验 server 身份",
    shortTitle: "Server Check",
    description: "Client 先校验证书链，再检查 server certificate URI SAN 是否等于 TARGET_AGENT_SPIFFE_ID。",
    evidence: "expected server id: spiffe://example.org/agent/worker",
    codeRefs: ["src/transport/spiffe-http-client.ts", "src/spiffe/peer-certificate.ts"],
    log: "server URI SAN matched expected target",
  },
  {
    id: "server-checks-client",
    index: 5,
    layer: "transport",
    actor: "Agent B",
    title: "Server 校验 client 身份",
    shortTitle: "Client Check",
    description: "Server 要求 client certificate，从 URI SAN 提取 caller SPIFFE ID。",
    evidence: "peer id: spiffe://example.org/agent/coordinator",
    codeRefs: ["src/transport/spiffe-http-server.ts", "src/spiffe/peer-certificate.ts"],
    log: "client certificate authorized by trust bundle",
  },
  {
    id: "authorize",
    index: 6,
    layer: "policy",
    actor: "PeerPolicy",
    title: "Policy 授权 caller / target / action",
    shortTitle: "Authorize",
    description: "TLS 层只确认 caller 是谁；Policy 层确认 coordinator 是否能调用 worker 的 agent:http。",
    evidence: "source=coordinator, target=worker, action=agent:http -> allow",
    codeRefs: ["src/policy/peer-policy.ts", "config/agent-policy.example.json"],
    log: "policy decision: allow",
  },
  {
    id: "handler",
    index: 7,
    layer: "runtime",
    actor: "Business Handler",
    title: "进入业务 handler",
    shortTitle: "Handler",
    description: "只有认证和授权都通过后，handler 才收到 context.peer.spiffeId，并返回 JSON 响应。",
    evidence: "response includes serverId and clientId",
    codeRefs: ["src/transport/spiffe-http-server.ts", "src/types.ts"],
    log: "handler completed with authenticated peer context",
  },
  {
    id: "observe",
    index: 8,
    layer: "observe",
    actor: "Audit Log",
    title: "记录审计字段",
    shortTitle: "Audit",
    description: "日志记录 localSpiffeId、peerSpiffeId、action、decision、certNotAfter；不记录 private key。",
    evidence: "private key never appears in logs",
    codeRefs: ["docs/runbooks/spire-runtime-checklist.md"],
    log: "audit event written without certificate secret material",
  },
];

export const failureScenarios: FailureScenario[] = [
  {
    id: "server-id-mismatch",
    title: "目标身份错误",
    trigger: "把 TARGET_AGENT_SPIFFE_ID 改成 spiffe://example.org/agent/other",
    expectedResult: "Client 在 server URI SAN 检查阶段拒绝连接。",
    blockedAtStepId: "client-checks-server",
  },
  {
    id: "policy-deny",
    title: "调用者未授权",
    trigger: "把 ALLOWED_CLIENT_SPIFFE_IDS 改成其他 ID，或删除 coordinator 的 policy rule",
    expectedResult: "Server 在 PeerAuthorizer 阶段返回 403，handler 不会执行。",
    blockedAtStepId: "authorize",
  },
  {
    id: "socket-missing",
    title: "Workload API 不可用",
    trigger: "SPIFFE_ENDPOINT_SOCKET 指向不存在的 socket",
    expectedResult: "IdentitySource 启动失败，server/client 不进入 TLS 阶段。",
    blockedAtStepId: "fetch-client-svid",
  },
];

export function createAuditEvents(): Array<Record<string, string>> {
  return [
    {
      localSpiffeId: "spiffe://example.org/agent/worker",
      peerSpiffeId: "spiffe://example.org/agent/coordinator",
      action: "agent:http",
      decision: "allow",
      certNotAfter: "rotating short-lived SVID",
    },
    {
      localSpiffeId: "spiffe://example.org/agent/worker",
      peerSpiffeId: "spiffe://example.org/agent/unknown",
      action: "agent:http",
      decision: "deny",
      reason: "caller is not allow-listed",
    },
  ];
}

export function getDemoSnapshot(host = "127.0.0.1", port = 5173, basePath = "", publicUrl?: string): DemoSnapshot {
  const normalizedBasePath = basePath === "/" ? "" : basePath.replace(/\/+$/, "");
  const localUrl = publicUrl ?? `http://${host}:${port}${normalizedBasePath}`;

  return {
    title: "SPIFFE mTLS Agent Interactive Demo",
    subtitle: "一个服务、一张页面，看完整 Agent mTLS 通信路径。",
    localUrl,
    basePath: normalizedBasePath,
    trustDomain: "example.org",
    actors: demoActors,
    layers: architectureLayers,
    steps: demoSteps,
    failureScenarios,
    commands: {
      install: "pnpm install",
      web: "pnpm demo:spiffe",
      server:
        "SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock AGENT_SPIFFE_ID=spiffe://example.org/agent/worker ALLOWED_CLIENT_SPIFFE_IDS=spiffe://example.org/agent/coordinator PORT=8443 pnpm start:server",
      client:
        "SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock AGENT_SPIFFE_ID=spiffe://example.org/agent/coordinator TARGET_AGENT_URL=https://worker.agents.svc:8443/ TARGET_AGENT_SPIFFE_ID=spiffe://example.org/agent/worker pnpm start:client",
    },
    auditEvents: createAuditEvents(),
  };
}