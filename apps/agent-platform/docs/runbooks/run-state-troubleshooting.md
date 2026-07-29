# Runbook：Run 状态排查与安全恢复

| 字段 | 值 |
| --- | --- |
| 版本 | `run-state-troubleshooting@1.0` |
| Owner | Platform On-call |
| 批准角色 | Run Owner；写控制/恢复另需相应 admin step-up |
| 最后复核 | 2026-07-27 |
| 最近演练 | 未在仓库内证明；以 staging E2E/fault gate 和演练 evidence 为准 |
| 升级路径 | Platform On-call → Workflow/Commit Owner → Incident Commander |

## 输入、权限与证据

需要 `runs:read` 与 `audit:read`；pause/resume/cancel 需要 `runs:control`。UNKNOWN recovery 需要
`actions:recover`、admin 和 phishing-resistant 身份。Kubernetes 只读诊断不得变更
Worker 副本或直接删除 Temporal workflow。

```bash
set -euo pipefail
: "${PLATFORM_BASE_URL:?HTTPS API URL required}"
: "${RUN_READ_TOKEN:?short-lived runs:read token required}"
: "${AUDIT_READ_TOKEN:?short-lived audit:read token required}"
: "${RUN_ID:?run UUID required}"
: "${INCIDENT_ID:?ticket required}"
namespace="${PLATFORM_NAMESPACE:-agent-platform}"
evidence_dir="evidence/${INCIDENT_ID}/run-${RUN_ID}"
mkdir -p "${evidence_dir}"; chmod 700 "${evidence_dir}"

curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --header "Authorization: Bearer ${RUN_READ_TOKEN}" \
  "${PLATFORM_BASE_URL%/}/v1/runs/${RUN_ID}" \
  > "${evidence_dir}/run.json"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --header "Authorization: Bearer ${RUN_READ_TOKEN}" \
  "${PLATFORM_BASE_URL%/}/v1/runs/${RUN_ID}/actions" \
  > "${evidence_dir}/actions.json"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --header "Authorization: Bearer ${AUDIT_READ_TOKEN}" \
  "${PLATFORM_BASE_URL%/}/v1/audit/runs/${RUN_ID}" \
  > "${evidence_dir}/audit.json"

kubectl --namespace "${namespace}" get deployment,pod \
  -o json > "${evidence_dir}/workloads.json"
kubectl --namespace "${namespace}" logs deployment/agent-worker \
  --since=30m --all-pods --prefix > "${evidence_dir}/agent-worker.log"
```

在处置前固定 `workflow_id/workflow_run_id`、plan version、correlation ID、Event sequence、
Git/image/prompt/model/tool/policy/catalog 版本与当前状态。审计导出失败时不要用普通日志
拼接替代；先恢复只读审计路径。

## 状态决策表

| 现象 | 强制检查 | 允许处置 | 禁止 |
| --- | --- | --- | --- |
| `PLANNING` 长时间无进展 | Planner Activity、模型 429/5xx/timeout、schema、deadline | 有界 retry 或批准 model route；超限 fail | 无限等待/未批准模型 |
| `EXECUTING` 无进展 | ready task、dependency、Temporal backlog/oldest age、Worker、tool circuit | 恢复已批准 Worker、降并发、pause 依赖节点 | 绕依赖执行 |
| `WAITING_APPROVAL` 积压 | notification、审批角色/step-up、payload hash、expires_at | 重发通知、升级审批、过期旧 Action | 代替审批人批准 |
| `COMMITTING` 卡住 | Action、provider request ID、幂等 lookup、Commit Worker | 转 UNKNOWN recovery Runbook | 手工再次发送 |
| `VERIFYING` 反复失败 | criterion、Evidence、读后验证、replan 次数 | 有限 replan 或人工接管 | 降低 must 标准 |
| `PAUSED` 无法恢复 | pause origin、cancel flag、deadline、terminal status | 修复依赖后调用 resume | 直接改 DB 状态 |
| 成本异常 | token/tool/duration 比率、重复工具、context、model route | pause Use Case，预算 Runbook | 静默扩预算 |

## Pause、回读与 Resume

```bash
: "${RUN_CONTROL_TOKEN:?runs:control token required}"
reason="${INCIDENT_ID}: dependency diagnosis"
jq -n --arg reason "${reason}" '{reason:$reason}' \
  > "${evidence_dir}/pause-request.json"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --request POST --header "Authorization: Bearer ${RUN_CONTROL_TOKEN}" \
  --header 'Content-Type: application/json' \
  --data-binary "@${evidence_dir}/pause-request.json" \
  "${PLATFORM_BASE_URL%/}/v1/runs/${RUN_ID}:pause" \
  > "${evidence_dir}/pause.json"

curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --header "Authorization: Bearer ${RUN_READ_TOKEN}" \
  "${PLATFORM_BASE_URL%/}/v1/runs/${RUN_ID}" \
  > "${evidence_dir}/paused-readback.json"
jq -e '.status=="paused"' "${evidence_dir}/paused-readback.json" >/dev/null
```

恢复前确认：没有新高风险 task；快照与 Event sequence 一致；待审批和 UNKNOWN 已登记；
依赖 health 正常；deadline/budget 仍有效。然后：

```bash
printf '{}\n' > "${evidence_dir}/resume-request.json"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --request POST --header "Authorization: Bearer ${RUN_CONTROL_TOKEN}" \
  --header 'Content-Type: application/json' \
  --data-binary "@${evidence_dir}/resume-request.json" \
  "${PLATFORM_BASE_URL%/}/v1/runs/${RUN_ID}:resume" \
  > "${evidence_dir}/resume.json"
```

独立 GET 回读状态，并观察至少一个新的有序 Event；恢复先从只读 task 开始。若 cancel
已请求、deadline/budget 超限或 pause origin 缺失，resume 必须 fail closed。

## UNKNOWN、取消和失败分支

- Action 进入 `unknown`：立即转 [`commit-unknown.md`](commit-unknown.md)，不得 resume
  触发 Commit。
- Worker/Temporal 状态未知：不要删除 Pod/workflow；先查 task queue、workflow history 和
  DB snapshot，确认 Activity 幂等边界。
- Event sequence 断裂或 snapshot/Event 不一致：停止恢复，保全 DB/Temporal evidence。
- pause 请求超时：先 GET readback；不要盲重发。
- terminal Run 不得 resume；需要新 Run 时使用新的业务请求和幂等键并链接原 incident。
- 跨租户迹象转 [`cross-tenant-leak.md`](cross-tenant-leak.md)；prompt injection 转对应
  安全 Runbook。

退出需 Run/Event/Temporal 状态一致、依赖健康、无未登记 UNKNOWN、SLO 无 fast burn。
证据上传不可变 store 后记录 SHA-256、签名、version ID 和保留期限；本地日志不算完成。
