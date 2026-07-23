# SPIRE Registration Entries

示例按 Kubernetes 工作负载建模。按真实 namespace、service account、trust domain 调整。完整跑通步骤见 `../../docs/runbooks/spire-runtime-checklist.md`。

## Node alias

```bash
spire-server entry create \
  -node \
  -spiffeID spiffe://example.org/ns/spire/sa/spire-agent \
  -selector k8s_psat:cluster:prod
```

## Coordinator Agent

```bash
spire-server entry create \
  -parentID spiffe://example.org/ns/spire/sa/spire-agent \
  -spiffeID spiffe://example.org/agent/coordinator \
  -selector k8s:ns:agents \
  -selector k8s:sa:agent-coordinator
```

## Worker Agent

```bash
spire-server entry create \
  -parentID spiffe://example.org/ns/spire/sa/spire-agent \
  -spiffeID spiffe://example.org/agent/worker \
  -selector k8s:ns:agents \
  -selector k8s:sa:agent-worker
```

## Authorization contract

SPIRE registration 只负责“谁能拿到哪个 SVID”。Agent 间“谁能调用谁、能做什么动作”在项目 policy 层完成，不写进 TLS 握手逻辑里。