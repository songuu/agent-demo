# SLI / SLO 与运营节奏

| SLI | SLO |
| --- | --- |
| Run 接受可用性 | 99.9% 月度 |
| 只读任务技术成功率 | ≥99% |
| 业务任务合格率 | Use Case 目标，基线示例 ≥97% |
| must Claim Evidence coverage | ≥99% |
| 写操作正确率 | 100%；任何已确认重复副作用为 Sev-1 |
| 审批通知延迟 | P95 <30 秒 |
| 取消响应 | P95 <10 秒 |
| Worker 故障恢复 | P95 <2 分钟 |

Run 接受可用性只使用真实 API 接受结果：

- 分子：`agent_run_accept_requests_total{outcome="accepted"}`；持久化创建成功或合法的
  idempotent readback 均为 accepted；
- 分母：`agent_run_accept_requests_total` 的 accepted 与 unavailable；仅服务端异常或
  持久层不可用计入 unavailable，客户端校验/冲突类 4xx 不污染可用性；
- recording rule：`agent:run_accept_availability:ratio5m`，月度 SLO 由同一原始 counter
  按月窗计算；不得用从未发出的 Run status 作为拒绝分母。

预算利用率是 Histogram 分布而非“最后一个 Run”的 Gauge；运营使用
`agent:budget_utilization:p95`。队列 backlog/oldest age 来自 Temporal
`DescribeTaskQueue`，Worker capacity 来自真实 Activity interceptor 的 active/max slots，
依赖健康来自进程 healthcheck。模型成本与时延按实际选择的 model/use case/tier 记录；
模型升级和 cache hit/miss 由实际路由/usage 记录，禁止使用 `unknown` 模型成本补数。

Sev-1 只由 `agent_security_events_total{outcome="confirmed"}` 的重复副作用、跨租户数据暴露、
Secret 暴露或失控外部写触发。被 TrajectoryGuard 阻断的注入、越权和危险写尝试记录为
`outcome="blocked"` 的 Sev-2/Sev-3 安全信号，不能冒充已发生事故。

所有结构化日志固定包含 `log_schema_version`、`service`、`environment`；在有效 span 内还包含
W3C `trace_id`/`span_id`。日志与 trace 只保留 correlation/run/workflow/plan/task/invocation/action
标识和 tenant hash，不记录原始 tenant ID、Secret 或业务内容。

每日检查 SLO、错误、队列、审批、UNKNOWN、安全、成本；每周检查失败任务、工具可靠性、
拒绝和 Eval 漂移；每月检查权限、Secret、配额、保留、容量、成本；每季度复核 Threat
Model、DR、Kill Switch 与供应链。