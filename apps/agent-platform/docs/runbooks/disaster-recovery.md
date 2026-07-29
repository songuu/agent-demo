# Runbook：灾难恢复与恢复演练

| 字段 | 值 |
| --- | --- |
| 版本 | `disaster-recovery@1.0` |
| Owner | Disaster Recovery SRE Owner |
| 批准角色 | Incident Commander + Database/Object Storage/Temporal Owner |
| 最后复核 | 2026-07-27 |
| 最近演练 | 未在仓库内证明；以签名 `disaster_recovery` gate report 的 drill 时间为准 |
| 升级路径 | Platform On-call → DR SRE Owner → Incident Commander/Security Owner |

## 恢复目标与硬门禁

| 资产 | RPO | RTO | 必须回读 |
| --- | --- | --- | --- |
| PostgreSQL | ≤5 分钟 | ≤30 分钟 | PITR backup ID、`alembic_version`、Run/Event/Action 一致性 |
| Artifact Object Storage | ≤5 分钟 | ≤60 分钟 | bucket/key/version ID、size、SHA-256、KMS、Object Lock/hold |
| Temporal | 已批准持久化目标 | ≤30 分钟 | namespace、history、Worker、长 Run 可继续且 Commit 不重放 |
| Policy/Prompt/Tool Catalog | Git 零或分钟 | ≤30 分钟 | commit/tag/content SHA-256 精确一致 |
| 区域栈 | ≤5 分钟 | ≤60 分钟 | 已签名 image、Helm identity、只读 E2E、SLO |

频率是发布硬门禁：每日恢复验证不超过 36 小时；DB+Artifact 季度演练不超过
100 天；区域 GameDay 半年演练不超过 200 天。区域演练至少两个 region。报告中每个
asset/backup/region 必须属于顶层签名 scope，三类 drill 的并集必须完整覆盖 scope。

## 权限和禁止项

需要受审计的 provider restore 权限、数据库只读验证角色、Artifact 版本读取权限、
Temporal namespace 管理权限、隔离 Kubernetes namespace 权限。禁止：

- 在 production 原地恢复或覆盖现有 DB/bucket/Temporal namespace；
- 自动重放 `COMMITTING/UNKNOWN`；
- DB downgrade、删除 backup/object version、解除 legal hold；
- 把 provider 凭据、JWT、DSN 写入证据；
- 把“备份任务成功”当作“恢复已验证”。

本仓库是 provider-neutral release contract，不包含云账户专属 restore API。实际 restore
命令必须来自已批准、版本化的 provider companion runbook，并在 evidence 中记录其
URI、版本、job/backup/asset ID。若 companion runbook 或权限缺失，本流程必须停止，
不能用临时命令替代或声称 DR 完成。

## 1. 宣布事件、冻结写入、固定目标

```bash
set -euo pipefail
: "${INCIDENT_ID:?incident or drill ID required}"
: "${RECOVERY_POINT_UTC:?approved RFC3339 recovery point required}"
: "${POSTGRES_BACKUP_ID:?provider backup/PITR source ID required}"
: "${ARTIFACT_BACKUP_IDS:?comma-separated version/snapshot IDs required}"
: "${TEMPORAL_BACKUP_ID:?Temporal persistence backup ID required}"
: "${RESTORE_REGION_PRIMARY:?primary isolated restore region required}"
: "${RESTORE_REGION_SECONDARY:?second region required}"
: "${APPROVED_IMAGE_DIGEST:?signed sha256 image digest required}"
: "${APPROVED_GIT_SHA:?40-char Git SHA required}"

case "${RECOVERY_POINT_UTC}" in *Z|*+*) ;; *) exit 2 ;; esac
test "${RESTORE_REGION_PRIMARY}" != "${RESTORE_REGION_SECONDARY}"
evidence_dir="evidence/${INCIDENT_ID}/dr"
mkdir -p "${evidence_dir}"
chmod 700 "${evidence_dir}"

jq -n \
  --arg incident_id "${INCIDENT_ID}" \
  --arg recovery_point "${RECOVERY_POINT_UTC}" \
  --arg postgres_backup_id "${POSTGRES_BACKUP_ID}" \
  --arg artifact_backup_ids "${ARTIFACT_BACKUP_IDS}" \
  --arg temporal_backup_id "${TEMPORAL_BACKUP_ID}" \
  --arg primary_region "${RESTORE_REGION_PRIMARY}" \
  --arg secondary_region "${RESTORE_REGION_SECONDARY}" \
  --arg image_digest "${APPROVED_IMAGE_DIGEST}" \
  --arg git_sha "${APPROVED_GIT_SHA}" \
  '{incident_id:$incident_id,recovery_point:$recovery_point,
    postgres_backup_id:$postgres_backup_id,
    artifact_backup_ids:($artifact_backup_ids|split(",")),
    temporal_backup_id:$temporal_backup_id,
    regions:[$primary_region,$secondary_region],
    image_digest:$image_digest,git_sha:$git_sha}' \
  > "${evidence_dir}/recovery-target.json"
```

执行 [`kill-switch.md`](kill-switch.md) 的 environment/global `writes`；冻结发布、
Commit Worker 流量和破坏性维护。必须独立 GET 回读 active switch 后才继续。

## 2. 调用批准的 provider restore automation

Database、Object Storage、Temporal Owner 分别运行已签名 companion runbook。每个结果
必须输出机器可读 JSON，至少包含：`job_id`、`asset_id`、`backup_id`、
`requested_recovery_point`、`restored_at`、`region`、`status=completed`、evidence URI。

```bash
: "${POSTGRES_RESTORE_RESULT:?path to signed provider result JSON required}"
: "${ARTIFACT_RESTORE_RESULT:?path to signed provider result JSON required}"
: "${TEMPORAL_RESTORE_RESULT:?path to signed provider result JSON required}"
for result in \
  "${POSTGRES_RESTORE_RESULT}" \
  "${ARTIFACT_RESTORE_RESULT}" \
  "${TEMPORAL_RESTORE_RESULT}"
do
  jq -e '.status=="completed" and (.job_id|length)>0 and
         (.asset_id|length)>0 and (.backup_id|length)>0 and
         (.evidence_uri|startswith("https://"))' "${result}" >/dev/null
  cp "${result}" "${evidence_dir}/$(basename "${result}")"
done
```

RESTORE API 返回成功只是开始，下面的独立数据面回读全部通过才算恢复。

## 3. PostgreSQL 独立验证

`RESTORED_DATABASE_URL` 只能指向隔离恢复实例；先用 provider asset ID/endpoint allowlist
校验，禁止 production endpoint。

```bash
: "${RESTORED_DATABASE_URL:?isolated restored PostgreSQL URL required}"
: "${EXPECTED_ALEMBIC_REVISION:?approved schema revision required}"
: "${RESTORED_DATABASE_ASSET_ID:?restored DB asset ID required}"
test "${RESTORED_DATABASE_ASSET_ID}" != "${PRODUCTION_DATABASE_ASSET_ID:?production DB asset ID required}"

psql "${RESTORED_DATABASE_URL}" --set ON_ERROR_STOP=1 --tuples-only \
  --command 'SELECT version_num FROM alembic_version' \
  > "${evidence_dir}/postgres-alembic.txt"
test "$(tr -d '[:space:]' < "${evidence_dir}/postgres-alembic.txt")" = \
  "${EXPECTED_ALEMBIC_REVISION}"

psql "${RESTORED_DATABASE_URL}" --set ON_ERROR_STOP=1 --csv \
  --command "SELECT now() AS verified_at,
                    (SELECT count(*) FROM agent_runs) AS runs,
                    (SELECT count(*) FROM run_events) AS events,
                    (SELECT count(*) FROM prepared_actions) AS actions,
                    (SELECT count(*) FROM artifacts) AS artifacts;
             SELECT count(*) AS orphan_events
             FROM run_events e LEFT JOIN agent_runs r ON r.run_id=e.run_id
             WHERE r.run_id IS NULL;
             SELECT count(*) AS orphan_actions
             FROM prepared_actions a LEFT JOIN agent_runs r ON r.run_id=a.run_id
             WHERE r.run_id IS NULL;
             SELECT count(*) AS broken_event_sequences FROM (
               SELECT run_id FROM run_events GROUP BY run_id
               HAVING min(sequence_no)<>1 OR max(sequence_no)<>count(*)
             ) broken;
             SELECT action_id,run_id,status,idempotency_key,payload_hash,updated_at
             FROM prepared_actions
             WHERE status IN ('committing','unknown')
             ORDER BY updated_at" \
  > "${evidence_dir}/postgres-consistency.csv"

grep -E '^0(,|$)' "${evidence_dir}/postgres-consistency.csv" >/dev/null
```

最后一组 `COMMITTING/UNKNOWN` 是必须人工登记的清单，不得自动清零；逐条使用
[`commit-unknown.md`](commit-unknown.md)。同时从 provider result 的
requested/actual recovery point 计算 RPO，从 restore start/end 计算 RTO，禁止手填。

## 4. Artifact 版本与内容验证

从恢复 DB 抽样覆盖所有 classification、legal hold、Receipt 和大文件。每个样本都要
使用持久化 `object_version_id`，流式下载到磁盘计算 SHA-256，不允许读入进程完整内存。

```bash
: "${RESTORED_ARTIFACT_BUCKET:?restored bucket required}"
: "${PRODUCTION_ARTIFACT_BUCKET:?production bucket identity required}"
test "${RESTORED_ARTIFACT_BUCKET}" != "${PRODUCTION_ARTIFACT_BUCKET}"

aws s3api get-bucket-versioning --bucket "${RESTORED_ARTIFACT_BUCKET}" \
  > "${evidence_dir}/bucket-versioning.json"
aws s3api get-public-access-block --bucket "${RESTORED_ARTIFACT_BUCKET}" \
  > "${evidence_dir}/bucket-public-access.json"
aws s3api get-bucket-encryption --bucket "${RESTORED_ARTIFACT_BUCKET}" \
  > "${evidence_dir}/bucket-encryption.json"
aws s3api get-object-lock-configuration --bucket "${RESTORED_ARTIFACT_BUCKET}" \
  > "${evidence_dir}/bucket-object-lock.json"
jq -e '.Status=="Enabled"' "${evidence_dir}/bucket-versioning.json" >/dev/null
jq -e '.PublicAccessBlockConfiguration |
       .BlockPublicAcls and .IgnorePublicAcls and
       .BlockPublicPolicy and .RestrictPublicBuckets' \
  "${evidence_dir}/bucket-public-access.json" >/dev/null
```

对审计批准的每个 sample 执行：

```bash
: "${ARTIFACT_KEY:?sample object key required}"
: "${ARTIFACT_VERSION_ID:?sample object version required}"
: "${ARTIFACT_EXPECTED_SHA256:?metadata SHA-256 required}"
: "${ARTIFACT_EXPECTED_SIZE:?metadata size required}"

aws s3api head-object \
  --bucket "${RESTORED_ARTIFACT_BUCKET}" \
  --key "${ARTIFACT_KEY}" \
  --version-id "${ARTIFACT_VERSION_ID}" \
  > "${evidence_dir}/artifact-head.json"
jq -e --argjson size "${ARTIFACT_EXPECTED_SIZE}" '.ContentLength==$size' \
  "${evidence_dir}/artifact-head.json" >/dev/null
aws s3api get-object \
  --bucket "${RESTORED_ARTIFACT_BUCKET}" \
  --key "${ARTIFACT_KEY}" \
  --version-id "${ARTIFACT_VERSION_ID}" \
  "${evidence_dir}/artifact-sample.bin" \
  > "${evidence_dir}/artifact-get.json"
test "sha256:$(sha256sum "${evidence_dir}/artifact-sample.bin" | cut -d ' ' -f 1)" = \
  "${ARTIFACT_EXPECTED_SHA256}"
```

restricted/secret/Receipt 样本还要执行 `get-object-retention` 与
`get-object-legal-hold`，回读 retain-until/ON 状态。验证后安全清理本地 sample；不得
删除恢复 bucket 中版本。

## 5. Temporal 与隔离应用恢复

```bash
: "${RESTORED_TEMPORAL_ADDRESS:?restored Temporal endpoint required}"
: "${RESTORED_TEMPORAL_NAMESPACE:?restored namespace required}"
: "${TEMPORAL_TLS_CERT:?client cert path required}"
: "${TEMPORAL_TLS_KEY:?client key path required}"

temporal workflow list \
  --address "${RESTORED_TEMPORAL_ADDRESS}" \
  --namespace "${RESTORED_TEMPORAL_NAMESPACE}" \
  --tls-cert-path "${TEMPORAL_TLS_CERT}" \
  --tls-key-path "${TEMPORAL_TLS_KEY}" \
  --output json > "${evidence_dir}/temporal-workflows.json"
jq -e 'type=="array" and length>0' "${evidence_dir}/temporal-workflows.json" >/dev/null
```

对至少一条长 Run 读取 workflow history，与 DB 的 `workflow_id/workflow_run_id` 对齐。
启动 Worker 前保持 writes Kill Switch；确认 recovery/commit task queue 隔离，且
`COMMITTING/UNKNOWN` 不会被普通 retry 重放。

使用批准的 DR Helm values 部署到唯一隔离 namespace：

```bash
: "${DR_HELM_VALUES_FILE:?approved isolated DR values required}"
: "${IMAGE_REPOSITORY:?signed image repository required}"
: "${TOOL_CATALOG_ID:?approved catalog ID required}"
: "${TOOL_CATALOG_DIGEST:?approved catalog digest required}"
dr_namespace="agent-platform-dr-${INCIDENT_ID,,}"

decoded_namespace="$(printf '%s' "${dr_namespace}" | tr -cd 'a-z0-9-')"
test "${decoded_namespace}" = "${dr_namespace}"
helm upgrade --install agent-platform-dr deploy/helm/agent-platform \
  --namespace "${dr_namespace}" --create-namespace \
  --values "${DR_HELM_VALUES_FILE}" \
  --set-string global.environment=staging \
  --set-string global.imageRepository="${IMAGE_REPOSITORY}" \
  --set-string global.imageDigest="${APPROVED_IMAGE_DIGEST}" \
  --set-string global.gitSha="${APPROVED_GIT_SHA}" \
  --set-string global.toolCatalogId="${TOOL_CATALOG_ID}" \
  --set-string global.toolCatalogDigest="${TOOL_CATALOG_DIGEST}" \
  --atomic --wait --timeout 20m
```

先调用 `scripts/verify_release.py --skip-smoke` 验证 identity/dependencies，再用
`external_write_policy=deny` 的专用 DR token 跑只读 E2E。不得在恢复演练中向真实外部
系统 Commit。

## 6. 区域 GameDay、切换与退出

半年演练必须在两个 region 用同一 Git SHA/image digest 重建并验证；记录 DNS/traffic
controller 变更、开始/完成时间与 observed RPO/RTO。实际切流需要 Incident Commander
逐步批准：只读 → Prepare → Commit。每阶段停止条件与 canary policy 一致。

退出条件：三类 provider restore 结果和数据面 readback 一致；RPO/RTO 达标；
Postgres/Artifact/Temporal/Policy/Prompt/Tool Catalog identity 一致；UNKNOWN 已登记；
只读 E2E/replay/SLO 通过；Owner 签名批准。

## 失败分支与证据

- restore job 状态 unknown：不得重发，先按 provider job ID 查询；仍未知则升级 Owner。
- RPO/RTO 超标：演练/恢复失败，禁止切流；记录实际值和纠正措施。
- DB 孤儿、Event sequence 断裂、Artifact hash/version 不符：停止 Worker 和切流。
- Temporal history 缺失或普通 Worker 获取 Commit recovery task：停止 Worker，保持 switch。
- 任一恢复目标解析为 production asset：立即退出，禁止执行后续命令。
- region 只有一个或 scope/drill 集合不一致：operational readiness gate 必须失败。

最终 gate report 必须符合 `deploy/ci/operational-gate-report.schema.json`，并由
`validate_operational_readiness.py` 校验 daily/quarterly/semiannual 新鲜度、资产集合、
backup/region scope、RPO/RTO。上传不可变 evidence store 后记录 SHA-256、签名、
version ID、retain-until 与 legal hold；本地报告不算完成。
