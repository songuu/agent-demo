# ADR-0002：隔离 commit-worker

状态：Accepted
Owner：Security Owner + Platform Owner

## Decision

`commit-worker` 使用独立 ServiceAccount、数据库角色、Credential Broker grant
和 NetworkPolicy。它没有公共 Service，不持有 OpenAI Key，且是唯一拥有 commit
scope 的 workload。`agent-worker` 只能 read/prepare。

进程边界同样是硬约束：`agent-platform-agent-worker` 只轮询 `agent-runs`，其
注册表不得包含 commit Activity；`agent-platform-commit-worker` 只轮询
`agent-commits`，不得装配模型客户端或 OpenAI Key。禁止用同一通用 worker
入口配不同参数来模拟隔离。Helm、Compose、ServiceAccount、数据库角色和
NetworkPolicy 必须保持这一边界一致。

Commit 执行前必须锁定 Action、验证 expiry/payload hash、重新授权并先执行
幂等 lookup。未知结果进入 UNKNOWN，不交给通用 retry。

## Rejected alternatives

- 把业务 token 注入通用 Agent 或 Sandbox。
- 把 commit tool 暴露给 Agent/MCP/Tool Search。
- 发生 Policy 故障时切换 allow-all。
