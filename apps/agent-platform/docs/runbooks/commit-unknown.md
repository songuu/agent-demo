# Runbook：Commit UNKNOWN 对账

| 字段 | 值 |
| --- | --- |
| 版本 | `commit-unknown@1.0` |
| Owner | Commit On-call + 业务系统 Owner |
| 批准角色 | Incident Commander；recovery 操作者必须是 admin + phishing-resistant auth |
| 最后复核 | 2026-07-27 |
| 最近演练 | 未在仓库内证明；以 `fault_injection` gate 的 Commit 行与 Incident-derived Eval 为准 |
| 升级路径 | Commit On-call → 业务系统 Owner → Incident Commander/Security Owner |

UNKNOWN 表示外部副作用可能已执行，也可能未执行。重复副作用风险按 Sev-1 处理。
禁止改变原幂等键、直接重发 Commit、手工改状态或删除 Event。

## 权限和输入

API 调用方需要 `runs:read`、`actions:recover`，角色包含 `admin`，并使用
phishing-resistant 身份。数据库检查只允许审计只读角色；不得读取/导出解密 payload。

```bash
set -euo pipefail
: "${PLATFORM_BASE_URL:?HTTPS production API URL required}"
: "${RECOVERY_BEARER_TOKEN:?short-lived admin recovery token required}"
: "${RUN_ID:?run UUID required}"
: "${ACTION_ID:?action UUID required}"
: "${INCIDENT_ID:?incident ticket required}"
case "${PLATFORM_BASE_URL}" in https://*) ;; *) exit 2 ;; esac

evidence_dir="evidence/${INCIDENT_ID}/unknown-${ACTION_ID}"
mkdir -p "${evidence_dir}"
chmod 700 "${evidence_dir}"
```

## 1. 暂停并保全证据

先按 [`kill-switch.md`](kill-switch.md) 激活最小 `capability`/`use_case` 的
`writes` switch；若范围不明，升级为 environment writes。随后暂停对应 Run，避免新
执行边界启动。

```bash
jq -n --arg reason "${INCIDENT_ID}: Commit UNKNOWN reconciliation" \
  '{reason:$reason}' > "${evidence_dir}/pause-request.json"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --request POST \
  --header "Authorization: Bearer ${RECOVERY_BEARER_TOKEN}" \
  --header 'Content-Type: application/json' \
  --data-binary "@${evidence_dir}/pause-request.json" \
  "${PLATFORM_BASE_URL%/}/v1/runs/${RUN_ID}:pause" \
  > "${evidence_dir}/pause-response.json"

curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --header "Authorization: Bearer ${RECOVERY_BEARER_TOKEN}" \
  "${PLATFORM_BASE_URL%/}/v1/runs/${RUN_ID}" \
  > "${evidence_dir}/run-before.json"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --header "Authorization: Bearer ${RECOVERY_BEARER_TOKEN}" \
  "${PLATFORM_BASE_URL%/}/v1/runs/${RUN_ID}/actions" \
  > "${evidence_dir}/actions-before.json"

jq -e --arg action_id "${ACTION_ID}" \
  'any(.[]; .action_id==$action_id and .status=="unknown")' \
  "${evidence_dir}/actions-before.json" >/dev/null
```

使用受审计的 DB 只读连接补充不可变快照。此查询不读取 `payload_encrypted`：

```bash
: "${AUDIT_DATABASE_URL:?audited read-only PostgreSQL URL required}"
psql "${AUDIT_DATABASE_URL}" --set ON_ERROR_STOP=1 \
  --set action_id="${ACTION_ID}" --csv \
  --command "SELECT action_id,run_id,tenant_id,action_type,tool_name,tool_version,
                    payload_hash,idempotency_key,policy_version,status,
                    receipt_json->>'provider_request_id' AS provider_request_id,
                    failure_code,expires_at,committing_at,updated_at,version
             FROM prepared_actions
             WHERE action_id = :'action_id'::uuid" \
  > "${evidence_dir}/action-audit.csv"
test "$(($(wc -l < "${evidence_dir}/action-audit.csv") - 1))" -eq 1
```

记录 Action、`payload_hash`、原 `idempotency_key`、adapter/provider request id、
tool/policy 版本和 Event sequence；不得改写原记录。

## 2. 启动唯一的 recovery workflow

生产 recovery workflow 内部调用 Adapter 的 `lookup_by_idempotency_key`；只有 provider
明确返回“未执行”时，才允许在同一幂等键上恢复。操作者不得自己重发业务请求。

```bash
jq -n '{operation:"reconcile"}' \
  > "${evidence_dir}/recover-request.json"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --request POST \
  --header "Authorization: Bearer ${RECOVERY_BEARER_TOKEN}" \
  --header 'Content-Type: application/json' \
  --data-binary "@${evidence_dir}/recover-request.json" \
  "${PLATFORM_BASE_URL%/}/v1/actions/${ACTION_ID}:recover" \
  > "${evidence_dir}/recover-accepted.json"

jq -e --arg action_id "${ACTION_ID}" --arg run_id "${RUN_ID}" \
  '.status=="accepted" and .operation=="reconcile" and
   .action_id==$action_id and .run_id==$run_id and (.workflow_id|length)>0' \
  "${evidence_dir}/recover-accepted.json" >/dev/null
```

不要因 HTTP timeout 重发。若响应未知，先查询 Temporal recovery workflow ID 与 Action
readback；仍未知时保持原状态并升级。

## 3. 独立回读并分类

```bash
deadline="$(( $(date +%s) + 900 ))"
while :; do
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --header "Authorization: Bearer ${RECOVERY_BEARER_TOKEN}" \
    "${PLATFORM_BASE_URL%/}/v1/runs/${RUN_ID}/actions" \
    > "${evidence_dir}/actions-latest.json"
  status="$(jq -er --arg id "${ACTION_ID}" \
    '.[] | select(.action_id==$id) | .status' \
    "${evidence_dir}/actions-latest.json")"
  case "${status}" in
    committed|failed|compensated|unknown) break ;;
  esac
  test "$(date +%s)" -lt "${deadline}" || exit 3
  sleep 5
done
cp "${evidence_dir}/actions-latest.json" "${evidence_dir}/actions-after.json"
```

分类规则：

- provider 已执行：保存 Receipt/`provider_request_id`，读后验证通过后 Action 必须为
  `committed`，并追加 `action.reconciled` Event；不得再次 Commit。
- provider 明确未执行且 Action 未过期：recovery 只能用原幂等键执行一次，再保存
  Receipt 和读后验证。
- provider 仍不确定、lookup 不受支持、或验证失败：保持 `unknown`，转人工；禁止生成
  新幂等键。
- 只有业务补偿已定义、可验证且获批准时，才另行调用
  `{"operation":"compensate","reason":"..."}`；reconcile 失败不等于可补偿。

用审计查询确认 receipt、verification 与 Event Log 一致：

```bash
psql "${AUDIT_DATABASE_URL}" --set ON_ERROR_STOP=1 \
  --set action_id="${ACTION_ID}" --set run_id="${RUN_ID}" --csv \
  --command "SELECT action_id,status,receipt_json,verification_json,failure_code,
                    idempotency_key,updated_at,version
             FROM prepared_actions WHERE action_id=:'action_id'::uuid;
             SELECT sequence_no,event_type,action_id,correlation_id,payload_hash,created_at
             FROM run_events
             WHERE run_id=:'run_id'::uuid AND action_id=:'action_id'::uuid
             ORDER BY sequence_no" \
  > "${evidence_dir}/reconciliation-readback.csv"
```

## 4. 退出与恢复

退出必须同时满足：外部状态、Receipt、verification、Action 快照和有序 Event 一致；
确认无重复副作用；影响评估和通知完成；最小复现进入 Incident-derived Eval。业务与
Security Owner 批准后，按只读 → Prepare → Commit 顺序恢复并解除 Kill Switch。

## 失败分支与证据

- recovery API 503：保持 UNKNOWN，检查 dedicated recovery/commit worker；不得改走通用
  Agent Worker。
- provider lookup 429/5xx：有界退避由 workflow 管理；操作者不循环 curl provider。
- DB/API readback 不一致：Sev-1，保全两侧证据并停止恢复。
- Action 已过期或 payload hash 漂移：fail closed，禁止 Commit。
- Kill Switch 或 pause 未回读：停止 recovery，不得假设已隔离。

证据包包含 pause、Action/Run 前后快照、只读 SQL、recovery workflow ID、provider
Receipt 引用、verification、Event、审批与 Kill Switch。上传不可变 evidence store 后
记录 SHA-256、签名、version ID、retain-until；本地文件不算完成。
