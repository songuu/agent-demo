# SPIFFE mTLS Agent 完整架构图

这张图覆盖项目级完整边界：信任平面、节点平面、Agent 运行时、mTLS 握手、授权策略、证书轮换、观测审计、部署入口。

![SPIFFE mTLS Agent 完整架构图](./spiffe-agent-mtls-complete-architecture.svg)

```mermaid
flowchart TB
  %% Complete project architecture for SPIFFE-based Agent-to-Agent mTLS.

  subgraph trustDomain["Trust Domain: example.org"]
    direction TB

    subgraph trustPlane["Trust Plane / Control Plane"]
      direction TB
      spireServer["SPIRE Server"]
      registrationApi["Registration API / Workload Entries"]
      nodeAttestor["Node Attestor"]
      workloadSelectors["Workload Selectors"]
      caIssuer["CA / X.509-SVID Issuer"]
      bundlePublisher["Trust Bundle Publisher"]
      federationBundle["Federated Bundles"]

      registrationApi --> spireServer
      nodeAttestor --> spireServer
      workloadSelectors --> registrationApi
      spireServer --> caIssuer
      caIssuer --> bundlePublisher
      bundlePublisher --> federationBundle
    end

    subgraph nodePlane["Node / Kubernetes Worker"]
      direction TB
      spireAgent["SPIRE Agent"]
      workloadApiSocket["Workload API Socket<br/>unix:///run/spire/sockets/agent.sock"]
      nodeIdentity["Node Attestation Identity"]
      selectorEvidence["Selector Evidence<br/>namespace / serviceAccount / process / uid"]

      nodeIdentity --> spireAgent
      selectorEvidence --> spireAgent
      spireAgent --> workloadApiSocket
      spireServer <-->|"attest node + fetch entries + bundles"| spireAgent
    end

    subgraph agentA["Agent A: coordinator"]
      direction TB

      subgraph runtimeA["Runtime"]
        envA["Environment / Config<br/>AGENT_SPIFFE_ID<br/>TARGET_AGENT_SPIFFE_ID<br/>SPIFFE_ENDPOINT_SOCKET"]
        cliA["src/cli.ts"]
        runA["src/runtime/run-agent.ts"]
        configA["src/runtime/config.ts"]
        envA --> cliA --> runA --> configA
      end

      subgraph identityA["Identity Layer"]
        x509SourceA["WorkloadApiX509Source"]
        protoA["Workload API Proto Adapter"]
        svidCacheA["Current X.509-SVID<br/>leaf cert + private key"]
        bundleCacheA["Trust Bundle Cache<br/>local + federated CA roots"]
        secureContextA["Client TLS SecureContext"]

        x509SourceA --> protoA
        x509SourceA --> svidCacheA
        x509SourceA --> bundleCacheA
        svidCacheA --> secureContextA
        bundleCacheA --> secureContextA
      end

      subgraph outboundA["Outbound Transport"]
        httpClientA["SpiffeMtlsAgentClient"]
        httpsAgentA["https.Agent<br/>cert/key/ca"]
        serverIdCheckA["Server SPIFFE ID Check<br/>URI SAN == expected target"]
        requestA["JSON / Agent RPC Request"]

        httpClientA --> httpsAgentA
        httpsAgentA --> serverIdCheckA
        serverIdCheckA --> requestA
      end

      subgraph policyA["Local Policy"]
        peerPolicyA["PeerPolicy"]
        allowListA["Allowed target IDs / actions"]
        peerPolicyA --> allowListA
      end

      configA --> x509SourceA
      configA --> httpClientA
      configA --> peerPolicyA
      secureContextA --> httpsAgentA
    end

    subgraph agentB["Agent B: worker"]
      direction TB

      subgraph runtimeB["Runtime"]
        envB["Environment / Config<br/>AGENT_SPIFFE_ID<br/>ALLOWED_CLIENT_SPIFFE_IDS<br/>SPIFFE_ENDPOINT_SOCKET"]
        cliB["src/cli.ts"]
        runB["src/runtime/run-agent.ts"]
        configB["src/runtime/config.ts"]
        envB --> cliB --> runB --> configB
      end

      subgraph identityB["Identity Layer"]
        x509SourceB["WorkloadApiX509Source"]
        protoB["Workload API Proto Adapter"]
        svidCacheB["Current X.509-SVID<br/>leaf cert + private key"]
        bundleCacheB["Trust Bundle Cache<br/>local + federated CA roots"]
        secureContextB["Server TLS SecureContext"]

        x509SourceB --> protoB
        x509SourceB --> svidCacheB
        x509SourceB --> bundleCacheB
        svidCacheB --> secureContextB
        bundleCacheB --> secureContextB
      end

      subgraph inboundB["Inbound Transport"]
        httpsServerB["SpiffeMtlsAgentServer"]
        tlsOptionsB["HTTPS TLS Options<br/>requestCert: true<br/>rejectUnauthorized: true"]
        clientCertB["Peer Certificate"]
        clientIdB["Client SPIFFE ID Extraction<br/>URI SAN -> spiffe://..."]
        handlerB["Business Handler<br/>context.peer.spiffeId"]

        httpsServerB --> tlsOptionsB
        tlsOptionsB --> clientCertB
        clientCertB --> clientIdB
        clientIdB --> handlerB
      end

      subgraph policyB["Authorization Layer"]
        peerAuthorizerB["PeerAuthorizer"]
        staticPolicyB["StaticPeerPolicy / future OPA"]
        decisionB["Decision<br/>allow / deny + reason"]

        peerAuthorizerB --> staticPolicyB
        staticPolicyB --> decisionB
      end

      configB --> x509SourceB
      configB --> httpsServerB
      configB --> peerAuthorizerB
      secureContextB --> tlsOptionsB
      clientIdB --> peerAuthorizerB
      decisionB --> handlerB
    end

    subgraph observability["Observability / Audit"]
      direction TB
      logs["Structured Logs"]
      metrics["Metrics<br/>handshake failure / authz deny / SVID expiry"]
      traces["Traces<br/>caller -> target -> action"]
      audit["Audit Fields<br/>localSpiffeId<br/>peerSpiffeId<br/>action<br/>decision<br/>certNotAfter"]
      logs --> audit
      metrics --> audit
      traces --> audit
    end

    subgraph deployment["Deployment Inputs"]
      direction TB
      k8sSa["Kubernetes ServiceAccount"]
      workloadEntry["SPIRE Workload Entry"]
      policyFile["config/agent-policy.example.json"]
      envFile["Runtime Env Vars"]
      k8sSa --> workloadEntry
      workloadEntry --> registrationApi
      policyFile --> peerPolicyA
      policyFile --> staticPolicyB
      envFile --> envA
      envFile --> envB
    end
  end

  workloadApiSocket -->|"FetchX509SVID stream<br/>SVID + bundle + updates"| protoA
  workloadApiSocket -->|"FetchX509SVID stream<br/>SVID + bundle + updates"| protoB

  requestA ==>|"1. TCP connect<br/>2. TLS ClientHello<br/>3. server cert chain<br/>4. client cert<br/>5. both verify bundle<br/>6. app request"| httpsServerB

  serverIdCheckA -.->|"reject if server URI SAN mismatch"| requestA
  clientIdB -.->|"authorize caller/target/action before handler"| decisionB

  x509SourceA -.->|"SVID rotation event"| secureContextA
  x509SourceB -.->|"SVID rotation event<br/>server.setSecureContext"| secureContextB

  httpClientA --> logs
  httpsServerB --> logs
  peerAuthorizerB --> metrics
  handlerB --> traces

  classDef trust fill:#eef6ff,stroke:#1d4ed8,color:#0f172a
  classDef node fill:#f0fdf4,stroke:#15803d,color:#0f172a
  classDef agent fill:#fff7ed,stroke:#c2410c,color:#0f172a
  classDef identity fill:#fefce8,stroke:#a16207,color:#0f172a
  classDef security fill:#fef2f2,stroke:#b91c1c,color:#0f172a
  classDef observe fill:#f5f3ff,stroke:#7c3aed,color:#0f172a

  class spireServer,registrationApi,nodeAttestor,workloadSelectors,caIssuer,bundlePublisher,federationBundle trust
  class spireAgent,workloadApiSocket,nodeIdentity,selectorEvidence node
  class envA,cliA,runA,configA,httpClientA,httpsAgentA,requestA,envB,cliB,runB,configB,httpsServerB,handlerB agent
  class x509SourceA,protoA,svidCacheA,bundleCacheA,secureContextA,x509SourceB,protoB,svidCacheB,bundleCacheB,secureContextB identity
  class serverIdCheckA,peerPolicyA,allowListA,tlsOptionsB,clientCertB,clientIdB,peerAuthorizerB,staticPolicyB,decisionB security
  class logs,metrics,traces,audit observe
```

## 读图顺序

1. `SPIRE Server` 按 `Workload Entry + selectors` 决定哪个 workload 可拿哪个 SPIFFE ID。
2. 每个节点的 `SPIRE Agent` 完成 node attestation 后，向本机 workload 暴露 `Workload API Socket`。
3. Agent 进程只连本机 socket，拿短期 `X.509-SVID + trust bundle`，不保存长期证书或共享 token。
4. Agent A 出站时使用自己的 SVID 建 TLS，并显式要求目标 ID 等于 `TARGET_AGENT_SPIFFE_ID`。
5. Agent B 入站时要求 client cert，从 URI SAN 提取 client SPIFFE ID，在 handler 前做 policy 授权。
6. Workload API stream 推送轮换事件，IdentitySource 更新 client agent / server secure context。
7. 日志和指标围绕 `localSpiffeId / peerSpiffeId / action / decision / certNotAfter`，避免记录私钥和完整证书。

## 安全边界

- Trust domain：决定证书链可信范围。
- SPIFFE ID：决定 workload 身份，不等同于权限。
- Policy：决定 caller 能否访问 target/action。
- Workload API socket：决定本机进程能否取得 SVID，必须靠权限、selector、service account 收紧。
- Expected server ID check：防止同 trust domain 内其他 workload 冒充目标 Agent。