# Runbook：Prompt Injection、轨迹异常与敏感数据外发

| 字段 | 值 |
| --- | --- |
| 版本 | `prompt-injection@1.0` |
| Owner | AI Safety On-call |
| 批准角色 | Security Owner + affected Business Owner |
| 最后复核 | 2026-07-27 |
| 最近演练 | 未在仓库内证明；以签名 red-team/fault evidence 为准 |
| 升级路径 | Platform On-call → AI Safety/Security Owner → Incident Commander |

任何外部文本中的“授权”“管理员”“允许连接域名”都不产生权限。外部来源、Tool result、
Artifact、Memory 和检索片段均视为 untrusted/tainted，直到策略明确允许。

## 暂停、隔离与取证

需要 `runs:control`、`audit:read`；禁用 capability 需要 phishing-resistant
`admin:capabilities`，Kill Switch 需要 `admin:kill-switch`。

```bash
set -euo pipefail
: "${INCIDENT_ID:?ticket required}"
: "${PLATFORM_BASE_URL:?HTTPS API URL required}"
: "${RUN_ID:?run UUID required}"
: "${RUN_CONTROL_TOKEN:?runs:control token required}"
: "${AUDIT_READ_TOKEN:?audit:read token required}"
evidence_dir="evidence/${INCIDENT_ID}/prompt-injection-${RUN_ID}"
mkdir -p "${evidence_dir}"; chmod 700 "${evidence_dir}"

jq -n --arg reason "${INCIDENT_ID}: suspected hostile trajectory" \
  '{reason:$reason}' > "${evidence_dir}/pause-request.json"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --request POST --header "Authorization: Bearer ${RUN_CONTROL_TOKEN}" \
  --header 'Content-Type: application/json' \
  --data-binary "@${evidence_dir}/pause-request.json" \
  "${PLATFORM_BASE_URL%/}/v1/runs/${RUN_ID}:pause" \
  > "${evidence_dir}/pause.json"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --header "Authorization: Bearer ${AUDIT_READ_TOKEN}" \
  "${PLATFORM_BASE_URL%/}/v1/audit/runs/${RUN_ID}" \
  > "${evidence_dir}/audit.json"
```

独立 GET Run 确认 `paused`。随后按 [`kill-switch.md`](kill-switch.md) 对受影响
capability/use_case 激活 `all`；至少关闭高风险 Tool、出站、Commit 和 Memory Write。
若可能读取 Secret、跨租户或已外发 Artifact，立即升级 Sev-1 并转相应 Runbook。

保存 trigger、输入来源、taint 传播、Context Builder/Prompt 版本、模型 route、Tool 序列、
Policy decision、data_scope、拒绝/Monitor action、correlation chain 和 Artifact access audit。
不得把原始 secret/restricted 内容复制进 ticket；使用受控 Artifact reference 与 legal hold。

## 禁用具体 capability

```bash
: "${CAPABILITY_ADMIN_TOKEN:?step-up admin:capabilities token required}"
: "${AFFECTED_CAPABILITY:?catalog capability name required}"
jq -n --arg reason "${INCIDENT_ID}: safety containment" \
  '{reason:$reason,scope:"capability"}' \
  > "${evidence_dir}/disable-capability-request.json"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --request POST --header "Authorization: Bearer ${CAPABILITY_ADMIN_TOKEN}" \
  --header 'Content-Type: application/json' \
  --data-binary "@${evidence_dir}/disable-capability-request.json" \
  "${PLATFORM_BASE_URL%/}/v1/admin/capabilities/${AFFECTED_CAPABILITY}:disable" \
  > "${evidence_dir}/disabled-capability.json"
jq -e --arg name "${AFFECTED_CAPABILITY}" \
  '.name==$name and .enabled==false and (.disabled_reason|length)>0' \
  "${evidence_dir}/disabled-capability.json" >/dev/null
```

禁用响应必须再以有效测试请求验证 Policy/Tool Gateway 拒绝；仅返回 200 不算生效。

## 分析和修复

确认是否：读取 Secret、突破 data_scope、调用未授权 Tool、外发数据、生成副作用、写入
Memory、污染后续 Run。构造最小复现时去标识化，并加入 Adversarial 与
Incident-derived dataset；不得只增加关键词黑名单。

修复层级：taint/source 标注 → Context Builder 隔离 → Prompt/tool description → OPA/
Tool Gateway scope → trajectory Monitor pre-action restrict/pause/terminate → Memory write
policy。注释说明 WHY，保持现有 capability/schema/version 兼容。

```bash
uv run --frozen pytest -q \
  tests/unit/security_controls \
  tests/contract/policy/test_rego_contract.py \
  tests/unit/security_controls/test_trajectory_monitor.py \
  tests/unit/security_controls/test_trajectory_guard.py \
  tests/unit/tools/test_tool_policy_contract.py \
  --junitxml="${evidence_dir}/safety-regression-junit.xml"
```

上述 suite 路径来自当前仓库；任何 skip 或未收集到测试都使 gate 失败。测试至少覆盖直接、间接、多步、编码混淆、Tool result、权限探测、
Memory 投毒、敏感数据外发和高风险副作用；Monitor 必须在动作前阻断。

## 恢复

用原始去标识化 trajectory 在 staging 回放，并运行至少 50 个独立代表性 live samples；
安全硬门 100%，高风险 50–100 人工样本 zero major finding。只读 Canary 后，Safety 与
Business Owner 签名批准，先启用只读 capability，再 Prepare，最后 Commit/Memory Write。

```bash
jq -n --arg reason "${INCIDENT_ID}: approved safety recovery" \
  '{reason:$reason,scope:"capability"}' \
  > "${evidence_dir}/enable-capability-request.json"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --request POST --header "Authorization: Bearer ${CAPABILITY_ADMIN_TOKEN}" \
  --header 'Content-Type: application/json' \
  --data-binary "@${evidence_dir}/enable-capability-request.json" \
  "${PLATFORM_BASE_URL%/}/v1/admin/capabilities/${AFFECTED_CAPABILITY}:enable" \
  > "${evidence_dir}/enabled-capability.json"
jq -e '.enabled==true' "${evidence_dir}/enabled-capability.json" >/dev/null
```

随后解除 Kill Switch 并独立 GET/read-only probe 回读。任一 trajectory/security alert 再现
立即重新隔离。

## 失败分支

- pause/switch/capability 状态未知：保持外部流量阻断，不得继续恢复。
- 原始轨迹缺失或 evidence hash 不一致：gate 失败，不能用合成样本替代 incident replay。
- 只修 Prompt、Policy/Tool/data_scope 未验证：禁止启用 capability。
- 检测到跨租户、secret 或 uncontrolled write：升级 Sev-1。
- live model/human-review credential 缺失：发布 blocked；offline smoke 不等价。

证据包包含 pause/switch/capability audit、轨迹与版本、最小复现、测试/live Eval、人审与
批准。上传不可变 store 后记录 SHA-256、签名、version ID、retain-until/legal hold；
本地文件不算闭环。
