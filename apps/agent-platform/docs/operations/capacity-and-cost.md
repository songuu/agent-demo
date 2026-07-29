# 容量、背压与全成本治理

本文定义生产容量边界、租户预算、跨副本控制、扩缩容信号和 staging 验收证据。它不把
单 Pod 的 semaphore、`PM2/Pod Running`、Helm 静态渲染或一次数据库读回等同于完整发布成功。

## 控制面与真相源

| 边界 | 真相源 | 作用域 | 失败语义 |
| --- | --- | --- | --- |
| HTTP 限流 | Redis 原子脚本 | IP、用户、租户、use case | Redis 不可用时 staging/prod 失败关闭 |
| Run 并发与预算预留 | PostgreSQL `run_capacity_reservations` | 租户 | `pg_advisory_xact_lock` 串行化同租户准入 |
| Run 排队压力 | Temporal `DescribeTaskQueue` | workflow/activity queue | 探针不可用时不接收新 Run |
| 模型/项目并发与熔断 | Redis lease、FIFO queue、shared circuit | project + model | lease 丢失立即取消仍在运行的调用 |
| 工具/端点并发与熔断 | Redis lease、FIFO queue、shared circuit | gateway + tool + version | 仅 provider 故障计入 circuit；背压不污染 circuit |
| 最终成本 | PostgreSQL append-only `cost_ledger_entries` | tenant + Run + component | UPDATE/DELETE trigger 拒绝修改，RLS 强制租户隔离 |

Redis 只保存短期容量 lease、排队票据和 circuit 状态，不是 Run 或成本的唯一真相源。Redis key
使用 HMAC 摘要和固定 cluster hash tag，不能包含租户、项目、模型、工具或 principal 原文。
所有 API、Agent Worker、Commit Worker 必须注入同一受控 `rediss://` 服务和 HMAC Secret；
NetworkPolicy 仅允许到 `quota-redis-proxy:6380`。

## 容量参数与背压顺序

生产默认值由 Helm `values.yaml` 的 `capacity`、`quota`、`modelReliability` 和 `toolGateway`
版本化管理：

- 租户最大 active Run：100；预留 lease 为 Run deadline + 300 秒。
- Temporal soft limit：backlog 500 或 oldest age 60 秒。
- Critical Run 可在 soft limit 后继续，但最多到 2 倍 hard limit；hard limit 对所有优先级拒绝。
- 模型和工具默认每 scope 20 in-flight、100 queued、queue timeout 5 秒。
- HTTP 限流按 IP、用户、租户、use case 分层执行，不能只按 API Pod 本地计数。

准入顺序是：身份/输入校验 → kill switch/policy → HTTP quota → Temporal queue 探针 →
PostgreSQL tenant concurrency/budget reservation → 持久化 Run → 绑定 reservation → 启动 workflow。
持久化 Run 失败时只释放尚未绑定的 reservation。相同 tenant + Idempotency-Key 映射到相同
HMAC reservation key，重试不重复占用容量。

## 租户日/月预算

默认日预算为 1000 USD，月预算为 20000 USD；生产可下调，不应在无审批时静默上调。
准入同时计算已结算不可变账本和仍 active 的预算预留：

| 利用率 | control level | 新工作行为 |
| --- | --- | --- |
| < 50% | normal | 正常准入 |
| 50%–<80% | midpoint | 正常准入并观测趋势 |
| 80%–<95% | restrict | 拒绝 low priority 新 Run |
| 95%–<100% | critical_only | 仅准入 Critical reconciliation 工作 |
| >=100% | stop | 拒绝所有新 Run/模型/工具调用 |

已进入 Commit 或 UNKNOWN reconciliation 的关键动作不能因预算阈值被中断；预算控制针对新调用，
外部副作用仍必须完成查询、核对、补偿或升级人工处理。最终实际成本超过 Run、日或月预算时，
账本仍先记录实际值，COMPLETED 转换随后以 `BUDGET_EXHAUSTED` 被阻断，不能隐藏超支事实。

## 六类全成本与费率目录

最终 Run 成本为：

`model + tool + sandbox(cpu + memory) + artifact(storage + transfer) + workflow + observability`

计算单位如下：

- Model：运行时按版本化模型价格目录累计的实际 token 成本。
- Tool：不可变 tool invocation 数 × `tool_call_usd`。
- Sandbox：实测 CPU-second × CPU rate + 实测 GiB-second × memory rate。
- Artifact：字节换算 GiB，按实际/默认保留天数折算 GiB-month，并计入传输 GiB。
- Workflow：Run wall-clock seconds × workflow rate。
- Observability：不可变 Run event 数 × event rate。

`deploy/catalogs/platform-cost-rates.v1.json` 是费率源；Helm 内嵌文件必须字节相同，并由
`global.costRateCatalogId` 与 `global.costRateCatalogDigest` 双重绑定。Agent Worker 只读挂载到
`/etc/agent-platform/cost-rates/catalog.json`。目录缺失、digest 不符、重复 JSON key、schema
不合法，或 sandbox task 缺少实测 CPU/memory 单位时，最终成本结算失败关闭，不能用估值冒充实际值。

最终 `cost_reconciliation` 写入 terminal Run event，六个 component 分别追加到不可变账本。
同一 Run + catalog + component 的 event id 是确定性的，Activity 重试不会重复计费。

## 指标与 HPA

低基数指标不含 tenant id、user id、run id：

- `agent_platform_cost_usd_total{environment,component,use_case,tenant_tier}`；
- `agent_success_cost_usd{environment,use_case,tenant_tier}`；
- `agent_tenant_budget_utilization_ratio{environment,period,control_level,tenant_tier}`；
- `agent_queue_backlog{environment,queue}` 和 `agent_queue_oldest_age_seconds`；
- `agent_capacity_utilization_ratio{environment,resource}`。

Prometheus recording rules提供全成本 rate、cost per successful Run、成功成本 P95、租户预算 P95、
请求率和队列最大值。Executive Dashboard 使用这些真实 series，不把 model-only cost 当作全成本。

Helm HPA 使用多信号：

- API：CPU + `agent_run_accept_rate5m`；
- Agent/Commit Worker：CPU + workflow/activity backlog + oldest age；
- scale-up 快速，scale-down 使用 5–10 分钟 stabilization，避免 backlog 短暂下降造成抖动。

集群必须由平台团队提供 Prometheus Adapter 映射，将 recording series 暴露为上述 External Metric
名称。发布验证必须读回 `external.metrics.k8s.io` 和 HPA conditions；只有 YAML 存在不能证明扩缩容有效。

## staging 容量场景

仓库 runner：`scripts/run_capacity_scenarios.py`。它只接受显式 `--environment staging` 和 HTTPS
base URL，Bearer token 只从环境变量读取；报告不写 token。六个场景是：

1. 基线 RPS 的 10 倍突发，持续 60 秒；接受 202 或具名 quota/backpressure 响应，不接受未知 5xx。
2. 同时创建 100 个 max-duration 3600 秒的长 Run。
3. 对受控 baseline/degraded tool probe 各采样，要求 degraded P95 至少为 baseline 的 5 倍且无 5xx。
4. 对隔离的低 quota principal 持续请求，所有样本必须为 429。
5. 以 1 MiB chunk 流式上传 50 MiB 和 200 MiB Artifact；客户端不构造完整 body。
6. 查询至少 1000 个真实 `pending_approval` action 与所属 Run，验证 Run 为
   `waiting_approval` 且 pending list 精确包含这些 action；这不是 1000 个 HTTP 同时审批写入。

示例：

```powershell
$env:CAPACITY_BASE_URL='https://staging-agent.example.com'
$env:CAPACITY_BEARER_TOKEN='<injected-secret>'
$env:CAPACITY_RELEASE_ID='12345-1'
$env:CAPACITY_GIT_SHA='<40-lowercase-hex>'
$env:CAPACITY_IMAGE_DIGEST='sha256:<64-lowercase-hex>'
.\.venv\Scripts\python.exe scripts\run_capacity_scenarios.py `
  --environment staging `
  --release-id $env:CAPACITY_RELEASE_ID `
  --git-sha $env:CAPACITY_GIT_SHA `
  --image-digest $env:CAPACITY_IMAGE_DIGEST `
  --report .artifacts\capacity\capacity-report.json `
  --baseline-rps 1 `
  --tool-baseline-path /controlled/tool/baseline `
  --tool-degraded-path /controlled/tool/latency-5x `
  --persistent-429-path /controlled/quota/exhausted `
  --approval-manifest .artifacts\capacity\pending-1000.jsonl `
  --approval-control-evidence .artifacts\capacity\pending-controls.json `
  --approval-control-evidence-uri https://evidence.example.com/capacity/sha256:<exact-file-sha256>
```

Runner 会严格校验并把 release ID、Git SHA 和 image digest 写入原始报告。capacity gate report
必须通过 `raw_capacity_report.uri` 与 `raw_capacity_report.sha256` 引用该报告的原始字节：
URI 必须是与 gate report 同源的 HTTPS 地址，且末端路径段精确等于
`sha256:<64-lowercase-hex>`。readiness validator
在本地目录模式和 Bearer fetch 模式都会读取原始字节、重算 digest、校验 staging/发布身份与
时效，随后从完整六场景重新派生 10x burst、100 long runs、5x tool P95、至少 200 个全 429
样本、50/200 MiB 服务端分块上传证据和至少 1000 个 pending approval 状态。gate 自报 check 与派生值不一致时
发布失败；只提供汇总标量不构成容量验收。

pending manifest 每行必须包含 `action_id/run_id/workflow_id/payload_hash/expires_at/cohort`，
不得用 manifest 行数代替 API 状态读回。`--approval-control-evidence` 是必需的外部证据输入：
它必须绑定本次 release/Git/image、manifest 原始 bytes SHA 和完整 action/run/workflow ID 集。
通知证据由逐 action immutable delivery receipt 派生；超时证据由真实 `expired` 读回派生；
资源证据由 closed/open workflow IDs、task-queue backlog 与 active-slot 回归派生。根文件和三个
子证据都对实际 UTF-8 bytes（包括空白与 Unicode 表示）重算 SHA，content URI 末段必须精确匹配。
validator 独立重算三项结论并拒绝自报布尔；缺少任一输入会 fail closed，而不是永久不可达。

Tool degraded path、429 principal 和 pending action seed 是 staging operator gate；runner 不提升 quota、
不创建管理员故障、也不自动改生产状态。报告 `passed=true` 只证明这次请求样本满足断言，还必须联合：

- Temporal workflow/activity backlog 与 oldest age；
- PostgreSQL reservation/ledger readback 和六类成本合计；
- Redis/control dependency health；
- HPA desired/current replicas、conditions 和扩缩容时间线；
- 模型/工具 429、retry、circuit、P95；
- Worker OOM/restart、PostgreSQL/模型配额 avalanche 为零；
- 50/200 MiB object size/hash、malware verdict 和进程 RSS 证据。

## 发布证据边界

本地可验证：目录 digest、迁移 head、RLS/trigger DDL、单元/集成测试、Helm 合同、runner 报告 schema。
外部 staging 才能验证：真实 10x/100/1000 负载、对象存储流式链路、Redis/Temporal/PostgreSQL
依赖健康、Prometheus Adapter、HPA 行为和云账单对账。缺少任一外部读回时，应报告“未验证”，
不得写成“发布并验证成功”。
