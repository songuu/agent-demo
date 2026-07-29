# 发布期观测资产

Agent Platform 拥有 Prometheus rules 与六个 Grafana dashboards；Prometheus
Operator、Prometheus、Alertmanager、Grafana sidecar、OTel Collector 与 Trace 查询后端由
平台团队预先部署。release workflow 不会用临时组件伪造这些依赖。

staging 与 production 的 Helm rollout 完成后，工作流调用
`deploy/ci/deploy_observability_assets.sh`。调用必须提供 `release_id`、Git SHA、image digest、
Grafana HTTPS API、Alertmanager HTTPS API 和 alert receiver receipt HTTPS API。API token 只从
调用方指定的环境变量间接读取；脚本把 Authorization header 写入权限为 `0600` 的临时文件，
不把 token 写入证据、命令行或日志。所有外部调用强制 TLS 1.2、禁止 redirect/insecure、设置
connect/total timeout，并在退出时终止 port-forward、resolve synthetic alert、删除临时文件。

环境级配置如下；staging 与 production 使用相同 key、不同 GitHub Environment 值：

| 类型 | 名称 | 最小权限 |
| --- | --- | --- |
| Variable | `AGENT_PLATFORM_GRAFANA_API_URL` | HTTPS base URL |
| Secret | `AGENT_PLATFORM_GRAFANA_API_TOKEN` | dashboard read |
| Variable | `AGENT_PLATFORM_ALERTMANAGER_API_URL` | HTTPS base URL |
| Secret | `AGENT_PLATFORM_ALERTMANAGER_API_TOKEN` | status/alert read + synthetic alert write/resolve |
| Variable | `AGENT_PLATFORM_ALERT_DELIVERY_RECEIPT_BASE_URL` | HTTPS receipt lookup base URL |
| Secret | `AGENT_PLATFORM_ALERT_DELIVERY_RECEIPT_TOKEN` | exact-environment receipt/evidence read |

这些 token 必须由 OIDC/Secret Broker 按单次 workflow run 短期签发，不能复用业务 release token、
长期管理员 token 或跨环境凭据。

## Fail-closed 运行时验证

脚本在写入前检查：

- `prometheusrules.monitoring.coreos.com` CRD 与 API resource 已存在；
- OTel Collector Service 同时暴露 OTLP gRPC `4317`、OTLP HTTP `4318` 和 health
  `13133`，存在 ready EndpointSlice，且 health endpoint 可访问；
- Grafana deployment 的 dashboard sidecar 使用 `LABEL=grafana_dashboard`，并以
  `NAMESPACE=ALL` 监控应用 namespace；若配置 `LABEL_VALUE`，其值必须为 `1`；
- 三个外部 base URL 都是无 userinfo/query/fragment 的 HTTPS URL，token 存在且无换行，
  HTTP/delivery timeout 位于允许范围。

前置条件满足后，脚本：

1. 为 PrometheusRule 添加 exact `release_id`、Git SHA、image digest annotation 并 apply；
2. 校验六个 dashboard 的稳定 UID/标题契约，为每个 JSON 注入
   `agent-platform-release-id:*`、`agent-platform-git-sha:*`、
   `agent-platform-image-digest:*` tags，生成带 `grafana_dashboard=1` 的 ConfigMap 并 apply；
3. 从 Kubernetes 回读 PrometheusRule/ConfigMap，核对 release identity、label 与六个对象；
4. 通过 Prometheus `/-/ready`、`/api/v1/targets`、`/api/v1/query`、
   `/api/v1/rules` 和 `/api/v1/alertmanagers` 验证真实 scrape/query/rule/Alertmanager 链路；
5. 通过内部和外部 Alertmanager `/api/v2/status` 验证真实 route/receiver 配置；
6. 写入 release-bound synthetic span，再按 trace ID 从 Trace backend 回读；
7. 对六个固定 UID 调用 Grafana `/api/dashboards/uid/{uid}`，逐一核对标题、Grafana
   runtime version 与三项 exact release tags；ConfigMap 读回不能替代该步骤；
8. 向 Alertmanager `/api/v2/alerts` 提交带
   `release_id/git_sha/image_digest/namespace/delivery_id` 的 synthetic alert，并从同一 API
   回读 exact labels；
9. 轮询 receiver `${receipt_base_url}/${delivery_id}`。lookup 必须返回 delivered、exact
   release identity、receiver、received_at、同源 HTTPS `evidence_uri` 与 SHA-256。脚本再下载
   digest-addressed immutable receipt，重算字节 SHA，并核对 receipt 内完整 alert labels；
10. 显式 resolve synthetic alert，生成 `production-observability.json`，并通过
    `observability-evidence.schema.json` 与 `validate_observability_evidence.py` 校验六 dashboard、
    freshness、release binding 和 content-addressed receiver receipt。

receiver lookup 返回：

```json
{
  "schema_version": "1.0",
  "status": "delivered",
  "delivery_id": "release-check-<sha256>",
  "release_id": "<release>",
  "git_sha": "<40-hex>",
  "image_digest": "sha256:<64-hex>",
  "receiver": "<receiver-id>",
  "received_at": "<RFC3339>",
  "evidence_uri": "https://same-origin/.../sha256:<64-hex>",
  "evidence_sha256": "sha256:<64-hex>"
}
```

不可变 evidence payload 必须重复上述 identity，并包含 receiver 实际收到的
`alert.labels`。lookup 成功但无法下载证据、跨 origin、hash 不符、旧 release、Grafana 仅有
ConfigMap、Alertmanager 仅有 config、alert 未送达或 cleanup 失败，都会阻止环境晋级。

## Operational readiness 与最终证据

`operational-readiness.json` 必须包含 `observability` gate；其不可变 gate report 至少证明
staging 的六 dashboard API 回读、synthetic alert API 回读、receiver delivery receipt 和
content-addressed receipt 已通过，scope 绑定 `observability` 与 `alert_receiver` 资产。
这是发布前能力演练，不是 production 送达声明。

production rollout 后重新执行上述完整链路，产生 exact-release
`production-observability.json`。该文件作为 22 项受治理组件中的
`production_observability` 发布到受治理 Artifact store，经过 VersionId、COMPLIANCE
retention、digest-addressed readback 后进入最终签名 release evidence。GitHub Artifact 只是
副本。

本仓库的静态测试、schema/validator 测试和 shell syntax 只能证明实现契约；没有真实集群、
短期 token、Grafana/Alertmanager/receiver API 与不可变 receipt readback 时，不得声称生产
端到端验证成功。工作流不会提供 mock/fallback 绕过该边界。
