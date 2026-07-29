# Agent Platform

面向企业生产环境的 Agent 平台：确定性控制平面负责生命周期，受限 Agent
执行平面只生成计划、证据、Artifact 与 ActionProposal，真实副作用只能经
Prepare → Approve → Commit → Verify 事务链路完成。

权威规范为仓库 `docs/GPT5.6_Agent_平台基础架构与实施规范_v1.0.docx`。
实现、部署、运行手册与可复现验收证据均保存在本应用目录中。

## 本地快速验证

```powershell
uv sync --frozen --extra dev
uv run pytest
uv run ruff check src tests
uv run mypy src
uv build
docker compose --profile local -f deploy/docker/docker-compose.yml config
```

启动完整本地依赖与五个独立进程：

```powershell
docker compose --profile local -f deploy/docker/docker-compose.yml up --build -d
docker compose --profile local -f deploy/docker/docker-compose.yml ps
```

`agent-api`、`agent-worker`、`commit-worker`、`outbox-worker` 与一次性
`retention-worker` 使用不同入口和最小环境变量；本地目录 secret broker
只通过专用 volume 在 API 与 outbox 之间共享。生产发布使用 Helm/Kustomize
资产，不复用开发环境凭证、volume 或数据库角色。生产 Artifact 上传必须经
受控 egress 的外部恶意软件扫描并取得绑定原始字节的 `clean` 证据；只有
固定平台生产者生成的规范 JSON 可携带 `trusted_generated` 证明，且绝不
标记为恶意软件 `clean`。本地 `structural_only` 状态不会冒充生产扫描。
生产前置条件与验证命令见 `deploy/README.md`。
