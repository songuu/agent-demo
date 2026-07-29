# Runbook：疑似跨租户数据泄露

| 字段 | 值 |
| --- | --- |
| 版本 | `cross-tenant-leak@1.0` |
| Owner | Security Incident Commander |
| 批准角色 | Incident Commander + Security/Privacy/Legal Owner |
| 最后复核 | 2026-07-27 |
| 最近演练 | 未在仓库内证明；以签名 red-team/fault evidence 为准 |
| 升级路径 | Platform On-call → Security IC → Privacy/Legal/Business Owner |

这是 Sev-1。优先停止损害和保全证据，不先优化用户体验。任何“可能跨租户”的命中都
按真实泄露处理，直到独立证据排除。

## 立即隔离

需要 phishing-resistant admin token、`admin:kill-switch`、`audit:read` 和受审计的
Kubernetes/DB/Object Storage 只读权限。令牌不得进入证据或 shell trace。

```bash
set -euo pipefail
: "${INCIDENT_ID:?Sev-1 incident ID required}"
: "${PLATFORM_BASE_URL:?HTTPS API URL required}"
: "${ADMIN_BEARER_TOKEN:?step-up admin token required}"
: "${AFFECTED_TENANT_ID:?tenant ID required}"
evidence_dir="evidence/${INCIDENT_ID}/cross-tenant"
mkdir -p "${evidence_dir}"; chmod 700 "${evidence_dir}"
```

按 [`kill-switch.md`](kill-switch.md) 先激活受影响 tenant/capability 的 `all`；范围不明
立即使用 environment/global `all`。必须 GET 回读 active switch。另在外部 traffic
controller 阻止受影响路径；应用 API 不可用时不能把外部阻断写成应用 switch 成功。

撤销受影响 signed URL、session、短时凭据和 ServiceAccount；保留撤销 job ID/时间，
不要在证据中保存凭据值。禁止直接删除 Pod、日志、Object version 或 DB 行。

## 保全与界定范围

```bash
: "${AUDIT_READ_TOKEN:?audit:read token required}"
: "${RUN_ID:?representative affected run required}"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --header "Authorization: Bearer ${AUDIT_READ_TOKEN}" \
  "${PLATFORM_BASE_URL%/}/v1/audit/runs/${RUN_ID}" \
  > "${evidence_dir}/run-audit.json"

namespace="${PLATFORM_NAMESPACE:-agent-platform}"
kubectl --namespace "${namespace}" get deployment,pod,networkpolicy \
  -o json > "${evidence_dir}/cluster-state.json"
kubectl --namespace "${namespace}" logs deployment/agent-api \
  --since=24h --all-pods --prefix > "${evidence_dir}/api.log"
kubectl --namespace "${namespace}" logs deployment/agent-worker \
  --since=24h --all-pods --prefix > "${evidence_dir}/worker.log"
```

保存 Trace/Event/Policy decision/Artifact access audit/DB audit/Tool/SSE/cache key 与完整版本
清单；原 evidence 只读。仅收集事件所需最小内容，原始 restricted/model 内容按法律与
retention policy 处理。

确认：源 tenant、误暴露 tenant、resource type/ID、数据 classification、时间窗、入口、
是否外发到 Tool/Model/Artifact/日志/Memory、是否产生外部副作用。关联
`correlation_id → run_id → workflow_id → task_id → action_id → tool_call_id → artifact_id`。

## 技术验证

在隔离恢复副本执行只读 SQL；应用角色必须 `NOBYPASSRLS`，禁止用 owner/superuser 证明
隔离。

```bash
: "${ISOLATED_DATABASE_URL:?isolated audited PostgreSQL URL required}"
psql "${ISOLATED_DATABASE_URL}" --set ON_ERROR_STOP=1 --csv \
  --command "SELECT rolname,rolsuper,rolbypassrls FROM pg_roles
             WHERE rolname=current_user;
             SELECT schemaname,tablename,rowsecurity,forcerowsecurity
             FROM pg_tables
             WHERE schemaname='public' AND tablename IN
               ('agent_runs','run_events','prepared_actions','artifacts','memory_records');" \
  > "${evidence_dir}/rls-readback.csv"
```

修复 RLS、cache key、retrieval filter、Artifact prefix/presign、Tool data_scope 或 session
binding 后，在隔离环境运行：

```bash
uv run --frozen pytest -q \
  tests/integration/persistence/test_postgres_platform_store.py \
  tests/integration/persistence/test_postgres_governance_adapters.py \
  tests/contract/api/test_memory_scope_contract.py \
  tests/contract/policy/test_rego_contract.py \
  --junitxml="${evidence_dir}/tenant-isolation-junit.xml"
```

还必须用两个真实测试 tenant 验证 API、DB、Cache、Artifact、Tool、Session、Memory 的
所有跨租户请求 100% 返回 404/空/deny（依接口隐藏策略），且同租户控制组成功。任何
skip、测试数据共享或 admin bypass 都使 gate 失败。

## 恢复

1. Security/Privacy/Legal 完成影响评估和通知决策；记录签名批准。
2. 原始攻击/泄露轨迹加入 adversarial 与 Incident-derived Eval。
3. 在隔离环境重放；RLS/Policy/Artifact/Tool tests 与 red-team 全部通过。
4. 只读、单测试 tenant Canary；观察访问 audit、跨租户告警和 SLO。
5. Incident Commander 与 Security Owner 批准后，按只读 → Prepare → Commit 解除 switch。

## 失败分支

- 无法确定范围：保持 global all；不得缩小 switch。
- 日志/trace 含敏感内容：限制 evidence 访问并启用 legal hold；不要复制扩散。
- credential/URL 撤销状态未知：视为仍有效，继续阻断相关入口。
- 修复只在 API 层通过、DB/Artifact/Tool 未验证：禁止恢复。
- 任一跨租户负测成功读取：重新进入 Sev-1 初始步骤。
- evidence hash/sequence 不一致：停止分析副本写入并升级 Security IC。

证据包包含 switch/traffic control、审计导出、访问日志、RLS readback、凭据撤销引用、
范围清单、测试/Eval、通知批准与版本。上传不可变 store 后记录 SHA-256、签名、version
ID、retain-until/legal hold；本地日志不算闭环。
