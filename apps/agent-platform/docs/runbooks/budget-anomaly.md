# Runbook：预算与成本异常

| 字段 | 值 |
| --- | --- |
| 版本 | `budget-anomaly@1.0` |
| Owner | FinOps Owner + Platform On-call |
| 批准角色 | Use-case Owner；预算放宽另需 FinOps/Business Owner |
| 最后复核 | 2026-07-27 |
| 最近演练 | 未在仓库内证明；以签名 `cost_budget` gate report 为准 |
| 升级路径 | Platform On-call → FinOps Owner → Business Owner/Incident Commander |

## 已实现边界

运行时以 Run 为原子记录模型 usage、token、tool-call、duration 和估算成本；50% 记录
中点、80% warning、95% 只允许关键节点/验证、100% fail closed 并返回
`BUDGET_EXHAUSTED`。`agent_cost_usd_total` 是估算指标，不是云账单。Tool/Sandbox/
Artifact/Workflow/Observability 的全成本、tenant 日/月预算与估算-账单对账必须来自签名
cost gate；缺少它们时不得声称成本治理完整。

## 取证与分解

```bash
set -euo pipefail
: "${INCIDENT_ID:?ticket required}"
: "${PROMETHEUS_URL:?HTTPS Prometheus URL required}"
: "${PROMETHEUS_BEARER_TOKEN:?short-lived metrics token required}"
: "${PLATFORM_BASE_URL:?HTTPS API URL required}"
: "${AUDIT_READ_TOKEN:?audit:read token required}"
evidence_dir="evidence/${INCIDENT_ID}/budget"
mkdir -p "${evidence_dir}"; chmod 700 "${evidence_dir}"

query() {
  name="$1"; expression="$2"
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --get --header "Authorization: Bearer ${PROMETHEUS_BEARER_TOKEN}" \
    --data-urlencode "query=${expression}" \
    "${PROMETHEUS_URL%/}/api/v1/query" > "${evidence_dir}/${name}.json"
  jq -e '.status=="success"' "${evidence_dir}/${name}.json" >/dev/null
}
query cost_rate 'agent:cost_usd:rate1h'
query token_rate 'agent:model_tokens:rate5m'
query budget_p95 'agent:budget_utilization:p95'
query budget_alert 'ALERTS{alertname="AgentBudgetUtilizationExceeded",alertstate="firing"}'
```

按 `use_case`、tenant tier、model/role、prompt/version、task、tool、environment 拆分；
定位 context 膨胀、重复结果、模型升级、循环、无效工具、cache miss 和异常输入。对异常
Run 导出审计：

```bash
: "${RUN_ID:?representative anomalous run required}"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --header "Authorization: Bearer ${AUDIT_READ_TOKEN}" \
  "${PLATFORM_BASE_URL%/}/v1/audit/runs/${RUN_ID}" \
  > "${evidence_dir}/run-audit.json"
```

不得在 trace/log 中导出原始 secret、restricted prompt 或完整模型内容。

## 止损

1. 对受影响 `use_case`/tenant/capability 激活 `writes` 或 `all` Kill Switch，并 GET 回读；
   参见 [`kill-switch.md`](kill-switch.md)。
2. 降低入口并发和批准预算；暂停低价值 Run，保留已产生 checkpoint/evidence。
3. 不改变在途 Run 的预算、价格 catalog 或 model route；需要新预算时创建新批准版本。
4. 95% 后只允许 must verification/安全收尾；100% 必须硬停止，不得静默续费。

## 估算与账单对账

```bash
: "${SIGNED_BILLING_EXPORT:?signed provider billing export JSON required}"
: "${SIGNED_USAGE_EXPORT:?signed platform usage export JSON required}"
jq -e '.signature_verified==true and (.period_start|length)>0 and
       (.period_end|length)>0 and (.total_usd|numbers)>=0' \
  "${SIGNED_BILLING_EXPORT}" >/dev/null
jq -e '.signature_verified==true and (.estimated_total_usd|numbers)>=0 and
       (.cost_components|type)=="object"' \
  "${SIGNED_USAGE_EXPORT}" >/dev/null
```

对账必须覆盖 model、tool、Sandbox、Artifact、Workflow、Observability，记录 estimate、
billed、差额、币种、价格 catalog version、tenant/day/month 与 Owner。若任何组件缺失，
`billing_reconciled` gate 必须失败。候选版本相对基线成本回归必须 ≤15%。

## 修复与强制回读

修复优先级：删除重复调用 → 限制 Context → 恢复批准 model route/cache → 修复循环 →
调整低价值能力。不得先提高预算掩盖缺陷。修复后重跑代表性 E2E/Eval，并比较：

- `cost_per_success`、tokens/tool calls per success；
- P50/P95 latency 与错误率；
- 估算-账单差异；
- candidate 相对 baseline 的成本回归 ≤15%；
- budget p95 ≤1，且无新的 BUDGET_EXHAUSTED retry storm。

只有 metrics 独立查询、签名账单对账和业务 Owner 批准都通过，才按只读 → 低价值能力
→ 全量顺序解除 switch。

## 失败分支与证据

- Prometheus/usage 缺数据：数据质量事件；不得按 0 成本处理。
- model label 为 `unknown`：不得补估价格，先修 route/usage 采集。
- provider bill 延迟：保持 gate pending，不能用估算代替 `billing_reconciled`。
- Run 已超预算仍继续：Sev-1，关闭该 use case 并保全 Event/Temporal history。
- 对账差异无法解释：暂停放量，升级 FinOps/Business Owner。

证据包括 PromQL 响应、Run audit、价格 catalog、usage/bill、修复前后 Eval、审批和
Kill Switch。上传不可变 store 并记录 SHA-256、签名、version ID、retain-until；本地
报表不算 gate 完成。
