# Architecture Rules

## SPIFFE mTLS Agent architecture diagram

- 完整架构图放在 `docs/architecture/spiffe-agent-mtls-complete-architecture.md`，覆盖 Trust Plane、Workload API、IdentitySource、mTLS transport、Policy、Observability、Deployment 输入。
- Agent 间认证必须区分身份验证和授权：TLS 校验证书链与 URI SAN SPIFFE ID，Policy 校验 caller/target/action。
- 证书生命周期由 Workload API stream 驱动；长期私钥不进入项目配置。

## Beginner-facing SPIFFE docs

- SPIFFE mTLS 文档必须同时给全景图、握手时序图、SVID 轮换图、代码地图，避免只给抽象架构。
- README 保持入口页职责；长教程放 `docs/tutorials/spiffe-mtls-agent-beginner-guide.md`。
- 新手路径区分“不接 SPIRE 的本地验证”和“接真实 SPIRE 的 mTLS 验证”，不能混成一个成功结论。

## Interactive architecture demo service

- 复杂安全架构需要一个可启动页面服务：`pnpm demo:web`，通过浏览器展示成功路径、失败路径、代码层映射。
- 页面 demo 只能声明“可视化学习”，不能替代真实 SPIRE mTLS e2e；README 必须保留这个边界。
## Agent demo monorepo app routing

- 根仓库只做 workspace / registry / deploy 编排；可运行子应用必须放在 `apps/<app-id>`，由子应用持有源码、测试、文档和 package scripts。
- 每个可部署子应用必须在 `app-registry.json` 声明 `workspace`、`deploy.basePath`、`deploy.port`、`deploy.healthPath` 和 `agentBuildShortcut`。
- 生产路由统一走宿主 Nginx `/agent-demo/<app>/` 前缀，Node app 必须支持 `BASE_PATH`，页面资产和 API 不能写死根路径。
- agent-build 只消费 shortcut 元数据并渲染入口；不能把某个子应用的路径硬编码成唯一特殊入口。
