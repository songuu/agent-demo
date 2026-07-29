# 生产 Tool Catalog 与 Enterprise Gateway

生产和 staging 不允许装配 `build_reference_registry()`。工具定义来自只读、
版本化 ConfigMap，启动时必须同时校验原始文件 SHA-256；任何缺失、重复
`name/version`、摘要漂移、`reference.*` Adapter 或非严格 Schema 都会使进程
fail closed。

示例目录位于
`deploy/catalogs/tool-catalog.v1.json`。发布系统应复制并由 Tool Owner、
Security、业务系统 Owner 审批，使用内容摘要命名不可变 ConfigMap，例如：

```text
agent-platform-tool-catalog-sha256-<前 16 位摘要>
```

Pod 同时接收目录路径、完整 `sha256:<64 hex>` 摘要和 ConfigMap 名；目录名或文件
内容变化都必须触发新版本发布，不允许原地覆盖。

## 调用边界

- Agent Worker 只能取得 `required_scopes`，只能执行 read/preview。
- Commit Worker 只能在审批后取得 `commit_scopes`，执行 lookup/commit/verify/
  compensate；长效业务 Secret 不进入 Agent、数据库、日志或请求正文。
- Adapter 只调用配置的 HTTPS Gateway 固定路径 `/v1/tool-operations`。Catalog
  的 `adapter_ref` 只是 Gateway 路由键，不能控制 URL。
- 请求绑定 request id、catalog digest、definition hash、tool name/version、
  operation、tenant/principal/scopes、短时 broker reference 和可用时的
  idempotency key。
- 响应必须原样绑定上述身份并提供 provider request id 与新鲜 UTC 时间戳；
  错误、过期、重放、Schema 漂移或任何绑定不一致都视为不可信依赖响应。
- Commit 的超时和传输异常进入 `UNKNOWN`，只能按 idempotency key 查询后恢复，
  禁止盲重试。

Gateway 本身通过 workload identity 读取 broker reference。静态 provider token、
Cookie 或 `Authorization` 默认头不得配置到 Adapter HTTP client。

## 上线前验收

1. 对真实 provider sandbox 执行 read、空结果、拒绝、429、5xx、timeout、分页和
   partial-result 契约测试。
2. 对每个 Action 执行 preview、重复 commit、响应丢失、lookup、read-after-write
   verify、compensate；确认真实 provider 只产生一次副作用。
3. 从审计导出读回 tool/catalog/version、policy decision、payload/result hash、
   provider request id、receipt 与 verification。
4. 验证 Agent ServiceAccount 无 business commit broker ref，Commit Worker 无模型
   API Key，并通过 NetworkPolicy 只可到各自 egress proxy/Gateway。
5. 对 Catalog 摘要漂移、Gateway 不可用、凭据过期/跨租户、输出 Schema 漂移进行
   fail-closed 故障演练。
