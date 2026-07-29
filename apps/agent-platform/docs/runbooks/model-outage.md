# Runbook：模型服务大面积不可用

| 字段 | 值 |
| --- | --- |
| 版本 | `model-outage@1.0` |
| Owner | Model Platform On-call |
| 批准角色 | Model Policy Owner；Critical Task fallback 另需 Safety Owner |
| 最后复核 | 2026-07-27 |
| 最近演练 | 未在仓库内证明；以 `fault_injection.model` 签名 evidence 为准 |
| 升级路径 | Platform On-call → Model Platform Owner → Incident Commander |

## 识别与取证

```bash
set -euo pipefail
: "${INCIDENT_ID:?ticket required}"
: "${PROMETHEUS_URL:?HTTPS Prometheus URL required}"
: "${PROMETHEUS_BEARER_TOKEN:?metrics token required}"
evidence_dir="evidence/${INCIDENT_ID}/model-outage"
mkdir -p "${evidence_dir}"; chmod 700 "${evidence_dir}"

query() {
  name="$1"; expression="$2"
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --get --header "Authorization: Bearer ${PROMETHEUS_BEARER_TOKEN}" \
    --data-urlencode "query=${expression}" \
    "${PROMETHEUS_URL%/}/api/v1/query" > "${evidence_dir}/${name}.json"
  jq -e '.status=="success"' "${evidence_dir}/${name}.json" >/dev/null
}
query model_errors 'agent:model_request:error_ratio'
query model_p95 'agent:model_latency:p95'
query upgrades 'agent:model_upgrade:rate5m'
query backlog 'agent:queue_backlog:max'
query oldest 'agent:queue_oldest_age:max'
query dependency 'agent:dependency_unavailable'
```

同时核对 provider 官方状态、429/5xx/timeout 分类、项目配额、区域 DNS/TLS/egress proxy、
model route/prompt/pricing catalog 版本。Provider 状态页不是本平台恢复证据；必须以实际
请求 metrics 与 Run/Event 为准。

## 止损与路由

1. 降低 model capability/use case 并发；暂停低优先级 Run，避免 retry storm。
2. 对持续失败范围激活 capability/use_case `all` Kill Switch，并 GET 回读；参见
   [`kill-switch.md`](kill-switch.md)。
3. 只允许 Model Policy 已批准的备用 model；Critical Task 不得降级到低于质量/安全门槛
   或未列入 allowlist 的 model。
4. 可等待长任务保存 durable checkpoint 后 pause；时效任务明确失败或人工接管。
5. 不修改在途 Run 已记录的 prompt/model route/catalog version；新 route 必须版本化。

Runtime retry 必须有界、指数退避并带 jitter；operator 不得循环 curl provider。429 不是
授权扩 quota；需要 quota 变更时由 Model/FinOps Owner 单独批准。

## 变更前静态检查与隔离验证

```bash
uv run --frozen pytest -q \
  tests/unit/agents/test_model_policy.py \
  tests/unit/agents/test_openai_runtime.py \
  tests/unit/agents/test_runtime_failure_branches.py \
  tests/unit/workflows/test_temporal_workflow_failures.py \
  --junitxml="${evidence_dir}/model-failure-junit.xml"
```

在 staging 对候选 route 运行 Golden/Edge/Adversarial/Production-sample live eval；必须绑定
候选 manifest、model/prompt/tool/policy 版本和真实 usage。关键安全/工具门槛 100%，
证据覆盖 ≥99%，critical tool selection ≥98%，成本回归 ≤15%，P95 回归 ≤20%。没有
真实 staging model credential 时 gate 保持 blocked，不能用 deterministic/offline 结果
替代 live evidence。

## 恢复与独立回读

Provider 恢复后分批释放 backlog：内部只读 → 低风险只读 → 代表性 production → 全量。
每阶段重新查询 model error ratio/P95、queue age、cost、cache、upgrade rate 和 SLO；观察
时间不得短于 canary policy。确认：

- 429/5xx/timeout 回到批准基线；
- queue oldest age 持续下降，无 retry storm；
- route 只使用批准 model，`unknown` model label 为零；
- live Eval 与人工高风险抽检无 major finding；
- 成本/延迟回归在硬阈值内。

上述全部满足并获 Model Policy Owner 批准后，按只读 → 全能力解除 Kill Switch。解除后
再次 GET 回读并保留 switch audit。

## 失败分支

- fallback 也失败：保持 pause/switch，禁止链式尝试未批准 model。
- usage/token 缺失或 model=`unknown`：fail closed；不得补估成本或质量。
- provider 恢复但 Eval 回归：保持流量关闭，回滚 model route/prompt version。
- backlog/oldest age 上升：停止放量并降低 admission；不得仅扩 Worker 掩盖 provider 瓶颈。
- Critical Task 无批准 fallback：人工接管或明确失败。

证据包括 provider 状态引用、PromQL、Run/Event、route/catalog、测试/live Eval、逐阶段
放量与批准。上传不可变 store 后记录 SHA-256、签名、version ID、retain-until；本地
截图或状态页链接不算恢复完成。
