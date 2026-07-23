# 本地 / Kubernetes SPIRE 跑通清单

这份清单只负责真实 SPIRE 环境准备。代码学习先看 [新手图文教程](../tutorials/spiffe-mtls-agent-beginner-guide.md)。

## 目标拓扑

```text
SPIRE Server
  -> SPIRE Agent on node
     -> Workload API socket
        -> coordinator Agent
        -> worker Agent
```

## 1. 确认 Workload API socket

```bash
ls -l /run/spire/sockets/agent.sock
```

应用进程必须能访问这个 socket。Kubernetes 中通常通过 volume mount 暴露给 Pod。

## 2. 注册 workload entry

示例见 [deploy/spire/registration-entries.md](../../deploy/spire/registration-entries.md)。核心关系：

| Workload | SPIFFE ID | selector |
| --- | --- | --- |
| coordinator | `spiffe://example.org/agent/coordinator` | `k8s:ns:agents` + `k8s:sa:agent-coordinator` |
| worker | `spiffe://example.org/agent/worker` | `k8s:ns:agents` + `k8s:sa:agent-worker` |

注意：SPIRE registration 只说明“这个 workload 能拿哪个身份”。谁能调用谁在项目 policy 层配置。

## 3. 启动 server

```bash
SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock \
AGENT_SPIFFE_ID=spiffe://example.org/agent/worker \
ALLOWED_CLIENT_SPIFFE_IDS=spiffe://example.org/agent/coordinator \
PORT=8443 \
pnpm start:server
```

## 4. 启动 client

```bash
SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock \
AGENT_SPIFFE_ID=spiffe://example.org/agent/coordinator \
TARGET_AGENT_URL=https://worker.agents.svc:8443/ \
TARGET_AGENT_SPIFFE_ID=spiffe://example.org/agent/worker \
pnpm start:client
```

## 5. 故意制造 3 个失败，确认安全边界有效

| 测试 | 操作 | 预期 |
| --- | --- | --- |
| 目标身份错误 | 把 `TARGET_AGENT_SPIFFE_ID` 改成 coordinator | client TLS 校验失败 |
| 调用者未授权 | 把 `ALLOWED_CLIENT_SPIFFE_IDS` 改成其他 ID | server 返回 403 |
| socket 不可用 | 改错 `SPIFFE_ENDPOINT_SOCKET` | 启动阶段失败 |

这些失败不是 bug，是 demo 的安全边界在工作。

## 6. 观测字段

生产日志建议至少包含：

```json
{
  "localSpiffeId": "spiffe://example.org/agent/worker",
  "peerSpiffeId": "spiffe://example.org/agent/coordinator",
  "action": "agent:http",
  "decision": "allow",
  "certNotAfter": "..."
}
```

禁止记录 private key。完整证书也不要默认记录。