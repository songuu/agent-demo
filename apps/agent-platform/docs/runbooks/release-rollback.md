# Runbook：发布回滚与前滚

| 字段 | 值 |
| --- | --- |
| 版本 | `release-rollback@1.0` |
| Owner | Release SRE Owner |
| 批准角色 | Incident Commander + Production Release Owner；安全事件另需 Security Owner |
| 最后复核 | 2026-07-27 |
| 最近演练 | 未在仓库内证明；生产 gate 必须提供签名、未过期的 rollback acknowledgment |
| 升级路径 | Platform On-call → Release SRE Owner → Incident Commander |

## 原则与进入条件

只回滚到已批准的 Helm revision 和已签名的 immutable image digest；禁止在
production 重建镜像。数据库只允许前滚迁移，Helm rollback 必须 `--no-hooks`，
避免旧 revision 的 migration hook 对已前滚 schema 执行旧 Alembic 代码。

自动发布只接受已签名 operational readiness 中明确批准的 previous Helm revision、
Git SHA、image digest、Tool Catalog ID/digest 和数据库兼容性确认。部署前必须读回当前
revision、manifest 与四个 workload，并证明它们精确等于该目标；不得根据 Helm history
的位置猜测“上一个版本”。

以下任一条件触发停止发布并评估回滚：hard gate 失败、Sev-1/Sev-2 安全告警、
SLO fast burn、重复外部副作用。高风险事故先执行
[`kill-switch.md`](kill-switch.md)，至少关闭 Commit。

所需权限和工具：production kubeconfig、Helm release 只读/rollback RBAC、
`kubectl`、`helm`、`jq`、`sha256sum`、当前源码 checkout，以及短时
`AGENT_PLATFORM_RELEASE_TOKEN`。令牌不得进入证据文件或 shell trace。

## 1. 固定输入并保存回滚前证据

所有变量都必须来自 Incident/Release approval，不得自动选择“上一个 revision”。

```bash
set -euo pipefail
: "${INCIDENT_ID:?incident ticket required}"
: "${APPROVED_PREVIOUS_REVISION:?approved Helm revision required}"
: "${APPROVED_PREVIOUS_GIT_SHA:?40-char Git SHA required}"
: "${APPROVED_PREVIOUS_IMAGE_DIGEST:?sha256 digest required}"
: "${APPROVED_PREVIOUS_TOOL_CATALOG_ID:?tool catalog ID required}"
: "${APPROVED_PREVIOUS_TOOL_CATALOG_DIGEST:?tool catalog digest required}"
: "${PLATFORM_BASE_URL:?HTTPS production URL required}"
: "${AGENT_PLATFORM_RELEASE_TOKEN:?short-lived smoke token required}"

namespace="${PLATFORM_NAMESPACE:-agent-platform}"
release="agent-platform"
evidence_dir="evidence/${INCIDENT_ID}/rollback"
mkdir -p "${evidence_dir}"
chmod 700 "${evidence_dir}"

helm history "${release}" --namespace "${namespace}" --max 30 --output json \
  > "${evidence_dir}/helm-history-before.json"
helm status "${release}" --namespace "${namespace}" --output json \
  > "${evidence_dir}/helm-status-before.json"
kubectl --namespace "${namespace}" get deployment,pod,job \
  --output json > "${evidence_dir}/workloads-before.json"
kubectl --namespace "${namespace}" get event \
  --sort-by=.metadata.creationTimestamp \
  > "${evidence_dir}/events-before.txt"

current_revision="$(jq -er '.version' "${evidence_dir}/helm-status-before.json")"
test "${APPROVED_PREVIOUS_REVISION}" != "${current_revision}"
```

## 2. 验证目标 revision，不执行写入

```bash
helm get values "${release}" --namespace "${namespace}" \
  --revision "${APPROVED_PREVIOUS_REVISION}" --all --output yaml \
  > "${evidence_dir}/target-values.yaml"
helm get manifest "${release}" --namespace "${namespace}" \
  --revision "${APPROVED_PREVIOUS_REVISION}" \
  > "${evidence_dir}/target-manifest.yaml"

grep -F -- "@${APPROVED_PREVIOUS_IMAGE_DIGEST}" \
  "${evidence_dir}/target-manifest.yaml" >/dev/null
grep -F -- "${APPROVED_PREVIOUS_GIT_SHA}" \
  "${evidence_dir}/target-manifest.yaml" >/dev/null
grep -F -- "${APPROVED_PREVIOUS_TOOL_CATALOG_DIGEST}" \
  "${evidence_dir}/target-manifest.yaml" >/dev/null
```

必须由数据库 Owner 确认目标应用版本兼容当前 `alembic_version`。若旧代码不兼容
当前 expand/migrate 状态，禁止回滚，改走前滚修复。不得执行 Alembic downgrade。

## 3. 执行回滚

```bash
helm rollback "${release}" "${APPROVED_PREVIOUS_REVISION}" \
  --namespace "${namespace}" \
  --no-hooks \
  --wait \
  --cleanup-on-fail \
  --timeout 20m

for deployment in agent-api agent-worker commit-worker outbox-worker; do
  kubectl --namespace "${namespace}" rollout status \
    "deployment/${deployment}" --timeout=10m
done
```

`--no-hooks` 是安全要求：production upgrade 的 migration Job 是
`pre-install,pre-upgrade` hook；回滚应用时保留已前滚数据库。若 incident 需要新的
schema 修复，必须通过新的受审 Alembic migration 前滚。

正式 release workflow 将 Helm upgrade 单独作为写入边界。只有该步骤成功、其后的
rollout、observability、identity smoke、组件证据或最终签名/readback 任一步失败时，
才执行上述单一已批准目标；Helm upgrade 自身失败由 `--atomic` 处理。回滚前若当前
manifest 既不是候选 digest、workload 也不是已批准目标，状态视为 UNKNOWN，禁止重发。

## 4. 独立回读

仅看到 Pod Ready 不算成功。必须验证 Helm revision、所有 workload image、健康依赖、
release identity、Tool Catalog、只读 smoke 和 Workflow replay。

```bash
helm status "${release}" --namespace "${namespace}" --output json \
  > "${evidence_dir}/helm-status-after.json"
rollback_revision="$(jq -er '.version' "${evidence_dir}/helm-status-after.json")"
test "${rollback_revision}" -gt "${current_revision}"
helm get manifest "${release}" --namespace "${namespace}" \
  > "${evidence_dir}/manifest-after.yaml"
grep -F -- "@${APPROVED_PREVIOUS_IMAGE_DIGEST}" \
  "${evidence_dir}/manifest-after.yaml" >/dev/null
grep -F -- "${APPROVED_PREVIOUS_GIT_SHA}" \
  "${evidence_dir}/manifest-after.yaml" >/dev/null
grep -F -- "${APPROVED_PREVIOUS_TOOL_CATALOG_DIGEST}" \
  "${evidence_dir}/manifest-after.yaml" >/dev/null

kubectl --namespace "${namespace}" get deployment \
  agent-api agent-worker commit-worker outbox-worker \
  -o json > "${evidence_dir}/deployments-after.json"
jq -e --arg digest "${APPROVED_PREVIOUS_IMAGE_DIGEST}" \
  'all(.items[].spec.template.spec.containers[]; .image | endswith("@" + $digest))' \
  "${evidence_dir}/deployments-after.json" >/dev/null

uv run --frozen python scripts/verify_release.py \
  --base-url "${PLATFORM_BASE_URL}" \
  --expected-git-sha "${APPROVED_PREVIOUS_GIT_SHA}" \
  --expected-image-digest "${APPROVED_PREVIOUS_IMAGE_DIGEST}" \
  --expected-tool-catalog-id "${APPROVED_PREVIOUS_TOOL_CATALOG_ID}" \
  --expected-tool-catalog-digest "${APPROVED_PREVIOUS_TOOL_CATALOG_DIGEST}" \
  --output "${evidence_dir}/release-verification.json"

uv run --frozen python scripts/replay_workflow_histories.py \
  --history-dir "${WORKFLOW_HISTORY_DIR:?approved history export required}" \
  --minimum-histories 2 \
  --output "${evidence_dir}/workflow-replay.json"
```

另外核对 `COMMITTING/UNKNOWN` Action 清单；它们不得因回滚自动重放。按
[`commit-unknown.md`](commit-unknown.md) 对账。Policy/Prompt/Tool 版本必须保持
在途 Run 已记录的版本；任何放宽 Policy 都需新审批。

## 5. 恢复流量与退出标准

先只读 Canary，再恢复 Prepare，最后恢复 Commit。至少观察既定 production window，
并确认：

- `/health`、`/ready` 及 dependency readback 全部为 `ok`；
- release Git/image/tool catalog 精确匹配批准值；
- Smoke Eval、SSE/Run 查询、只读 E2E、Workflow replay 全部通过；
- SLO 无 fast burn，成本在预算内，重复外部副作用为零；
- UNKNOWN 已登记且没有自动重放；Incident Commander 批准解除 Kill Switch。

## 失败分支

- Helm rollback 失败：保持 Kill Switch；保存 `helm status`、Pod describe、events 和
  当前/目标 manifest；不得自动尝试另一个 revision。
- workload Ready 但 identity 不匹配：视为失败，保持流量关闭并前滚到唯一批准 digest。
- migration/schema 不兼容：禁止 DB downgrade；构建、签名、Canary 一个前滚修复。
- smoke/replay/SLO 任一失败：停止恢复流量；保留失败 Run/trace/Event/Artifact。
- kube API 或 Helm 状态未知：不要重发 rollback，先读回 release revision 和 workload
  digest；仍未知则升级 Incident Commander。

## 证据归档

证据包包含审批、前后 Helm 状态、target values/manifest、workload readback、
release verification、replay、SLO/告警窗口、Kill Switch 与 UNKNOWN 清单。上传不可变
Artifact/evidence store 后记录 SHA-256、签名、object version ID、retain-until 和 legal
hold；本地目录或 GitHub run 页面 fragment 不算已归档。
