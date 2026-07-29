# §22 验收矩阵

状态含义：`asset-ready` 表示本仓库已有自动化/文档入口，不代表生产环境已验证；
`runtime-evidence-required` 必须由集成、staging 或生产读回补齐。

## Architecture

| ID | 验收 | 证据入口 | 状态 |
| --- | --- | --- | --- |
| AR-01 | 三循环边界 | ADR-0001、依赖测试 | asset-ready |
| AR-02 | Agent 无 commit/长期凭证/任意网络 | ADR-0002、Helm、NetworkPolicy | asset-ready |
| AR-03 | Schema 版本化 | Prompt/Eval manifests、契约测试 | asset-ready |
| AR-04 | 状态独立于模型、长 Run 恢复 | Workflow kill/restart E2E | runtime-evidence-required |
| AR-05 | 外部能力经 Gateway | Tool catalog 与静态依赖测试 | runtime-evidence-required |
| AR-06 | 偏离有 ADR/Owner/到期 | `docs/adr`、季度复核 | asset-ready |

## Function

| ID | 验收 | 状态 |
| --- | --- | --- |
| FN-01 | POST Run 返回 202/run_id/links | runtime-evidence-required |
| FN-02 | 合法 DAG、依赖并行、有界重试 | runtime-evidence-required |
| FN-03 | Worker 仅 Task allowlist，WorkerOutput | runtime-evidence-required |
| FN-04 | Verifier 阻止证据/环境/must 失败 | runtime-evidence-required |
| FN-05 | cancel/pause/resume/timeout/replan/terminal | runtime-evidence-required |
| FN-06 | Action 到补偿 E2E | runtime-evidence-required |
| FN-07 | Artifact upload/scan/hash/download/expire/delete | runtime-evidence-required |
| FN-08 | SSE Last-Event-ID 续传 | runtime-evidence-required |

## Security

| ID | 验收 | 门槛/证据 |
| --- | --- | --- |
| SEC-01 | API/DB/Cache/Artifact/Tool/Session 跨租户 | 100% 拒绝 |
| SEC-02 | 直接/间接/多步注入 | Adversarial hard gate |
| SEC-03 | Secret/日志/Trace | 零 High/Critical |
| SEC-04 | Sandbox 逃逸/网络/资源/文件 | 默认 deny，零 High/Critical |
| SEC-05 | payload hash/auth/expiry/双人 | 100% 强制 |
| SEC-06 | 多级 Kill Switch | 目标响应时间内 |
| SEC-07 | 依赖/镜像/SBOM/签名/IaC | 零未接受 High/Critical |

## Reliability

| ID | 验收 | 证据 |
| --- | --- | --- |
| REL-01 | 各边界 kill 后恢复 | fault-injection E2E |
| REL-02 | 依赖故障无无限 retry | Workflow tests |
| REL-03 | UNKNOWN 无重复 | Incident Eval + provider sandbox |
| REL-04 | DB/Artifact 满足 RPO/RTO | DR 演练 |
| REL-05 | 历史 replay 无确定性错误 | release gate |
| REL-06 | cancel/Kill Switch 不启动高风险步骤 | security E2E |

## Operations

| ID | 验收 | 证据 |
| --- | --- | --- |
| OPS-01 | Run/Task/Model/Tool/Policy/Action/Cost telemetry | OTel/Prometheus |
| OPS-02 | Dashboard/SLO/Alert/Runbook 演练 | 六类 Grafana API readback + receiver immutable delivery receipt + GameDay |
| OPS-03 | Golden/Edge/Adversarial/Incident Eval | release gate |
| OPS-04 | Claim/Evidence/Artifact/version/Receipt 可追溯 | E2E audit export |
| OPS-05 | cost/latency/budget 可分析 | Executive/Model Dashboard |
| OPS-06 | On-call 可暂停/禁 Tool/UNKNOWN/恢复 | Runbook 演练 |

项目 DoD 还要求完整发布证据、培训、观察窗口、回滚 Owner，以及没有未接受的
Critical/High 或硬门禁失败。仅“模型能回答”不构成完成。
