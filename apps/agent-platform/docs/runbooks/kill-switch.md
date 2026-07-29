# Runbook：Kill Switch 激活、回读与恢复

| 字段 | 值 |
| --- | --- |
| 版本 | `kill-switch@1.0` |
| Owner | Platform On-call |
| 批准/解除 | Incident Commander；安全事件另需 Security Owner |
| 最后复核 | 2026-07-27 |
| 最近演练 | 未在仓库内证明；以签名的 `fault_injection` gate report 为准 |
| 升级路径 | Platform On-call → Incident Commander → Security/SRE Owner |

## 适用范围与权限

Kill Switch 是持久化、带审计的生产控制面。它支持 `global`、`environment`、
`tenant`、`use_case`、`capability` 五类 scope，以及：

- `writes`：保留查询和必要的只读诊断，阻止外部副作用；
- `all`：阻止新的执行边界；审计查询仍可用。

调用方必须持有 `admin:kill-switch` scope，并完成 phishing-resistant step-up。
不得把 JWT 写入命令历史、日志或证据包。

```bash
set -euo pipefail
: "${PLATFORM_BASE_URL:?HTTPS production API URL required}"
: "${ADMIN_BEARER_TOKEN:?short-lived step-up token required}"
: "${INCIDENT_ID:?incident ticket required}"
case "${PLATFORM_BASE_URL}" in https://*) ;; *) exit 2 ;; esac

evidence_dir="evidence/${INCIDENT_ID}/kill-switch"
mkdir -p "${evidence_dir}"
chmod 700 "${evidence_dir}"
```

## 激活

先选择最小有效范围。只有影响无法界定时才使用 `global/all`。以下示例关闭生产
环境全部新执行；其他 scope 必须把 `scope_id` 改为真实 tenant/use case/capability。

```bash
scope="${KILL_SWITCH_SCOPE:-environment}"
scope_id="${KILL_SWITCH_SCOPE_ID:-prod}"
mode="${KILL_SWITCH_MODE:-all}"
reason="${KILL_SWITCH_REASON:?human-readable reason required}"

curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --header "Authorization: Bearer ${ADMIN_BEARER_TOKEN}" \
  "${PLATFORM_BASE_URL%/}/v1/admin/kill-switches" \
  > "${evidence_dir}/before.json"

jq -n \
  --arg scope "${scope}" \
  --arg scope_id "${scope_id}" \
  --arg mode "${mode}" \
  --arg reason "${reason}" \
  --arg incident_id "${INCIDENT_ID}" \
  '{scope:$scope,scope_id:$scope_id,mode:$mode,reason:$reason,incident_id:$incident_id}' \
  > "${evidence_dir}/activate-request.json"

curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --request POST \
  --header "Authorization: Bearer ${ADMIN_BEARER_TOKEN}" \
  --header 'Content-Type: application/json' \
  --data-binary "@${evidence_dir}/activate-request.json" \
  "${PLATFORM_BASE_URL%/}/v1/admin/kill-switches" \
  > "${evidence_dir}/activated.json"

switch_id="$(jq -er '.switch_id' "${evidence_dir}/activated.json")"
jq -e \
  --arg id "${switch_id}" \
  --arg scope "${scope}" \
  --arg scope_id "${scope_id}" \
  --arg mode "${mode}" \
  '.switch_id==$id and .scope==$scope and .scope_id==$scope_id and
   .mode==$mode and .deactivated_at==null' \
  "${evidence_dir}/activated.json" >/dev/null
```

## 强制回读

激活接口成功不等于控制已生效。必须重新读取独立请求，并执行一个不会产生副作用
的拒绝探针。探针使用唯一幂等键；期望 HTTP 503 和对应
`GLOBAL/ENVIRONMENT/TENANT/USE_CASE/CAPABILITY_KILL_SWITCH_ACTIVE` 错误码。

```bash
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --header "Authorization: Bearer ${ADMIN_BEARER_TOKEN}" \
  "${PLATFORM_BASE_URL%/}/v1/admin/kill-switches" \
  > "${evidence_dir}/active-readback.json"
jq -e --arg id "${switch_id}" \
  'any(.[]; .switch_id==$id and .deactivated_at==null)' \
  "${evidence_dir}/active-readback.json" >/dev/null
```

对 `all` 模式，使用专门的无写测试租户令牌执行仓库合同测试同构的 create-run
探针；不得用真实业务租户。若返回 202，立即按 Sev-1 升级，保持外部流量控制器
关闭写流量，并保存响应。

## 解除

解除前必须同时满足：根因已修复；回归/回放通过；UNKNOWN 清单已对账；SLO 无
fast burn；Incident Commander 明确批准。安全事件还需 Security Owner 批准。

```bash
: "${DEACTIVATION_REASON:?approved deactivation reason required}"
jq -n --arg reason "${DEACTIVATION_REASON}" '{reason:$reason}' \
  > "${evidence_dir}/deactivate-request.json"

curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --request POST \
  --header "Authorization: Bearer ${ADMIN_BEARER_TOKEN}" \
  --header 'Content-Type: application/json' \
  --data-binary "@${evidence_dir}/deactivate-request.json" \
  "${PLATFORM_BASE_URL%/}/v1/admin/kill-switches/${switch_id}:deactivate" \
  > "${evidence_dir}/deactivated.json"

jq -e '.deactivated_at != null' "${evidence_dir}/deactivated.json" >/dev/null
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --header "Authorization: Bearer ${ADMIN_BEARER_TOKEN}" \
  "${PLATFORM_BASE_URL%/}/v1/admin/kill-switches" \
  > "${evidence_dir}/after.json"
jq -e --arg id "${switch_id}" 'all(.[]; .switch_id != $id)' \
  "${evidence_dir}/after.json" >/dev/null
```

先恢复只读 Canary，再恢复 Prepare，最后恢复 Commit。任一 gate 失败时重新激活
原 switch，不得用不同 incident ID 隐藏时间线。

## 失败分支与证据

- API 不可用：在外部流量控制器执行同范围阻断；不得声称应用 Kill Switch 已生效。
- 激活成功但拒绝探针失败：Sev-1，关闭入口与 Commit Worker 流量并保全证据。
- 解除请求失败：保持 active，禁止直接改库。
- 自动过期只用于低风险临时控制；Sev-1/Sev-2 不得依赖 `expires_at` 自动解除。

证据包至少包含 before/request/activated/readback/deactivate/after、incident
批准、拒绝探针、时间戳、release/git/image identity。上传不可变 evidence store 后
记录 version ID、SHA-256、签名与保留期限；本地文件不等于已归档。
