# Agent Demo Monorepo

这个仓库是 Agent 子应用集合。根目录只负责 workspace、应用注册、部署入口；具体业务应用放在 `apps/*`。

## 当前应用

| App | 路径 | 本地启动 | 生产路由 |
| --- | --- | --- | --- |
| SPIFFE mTLS Agent | `apps/spiffe-mtls-agent` | `pnpm demo:spiffe` | `/agent-demo/spiffe/` |

查看 registry：

```bash
pnpm apps:list
```

## 本地运行

```bash
pnpm install
pnpm demo:spiffe
```

打开 `http://127.0.0.1:5173`。页面会展示完整 SPIFFE/SPIRE Agent mTLS 过程：registration、Workload API 取 SVID、Client 校验 Server SPIFFE ID、Server 校验 Client SPIFFE ID、Policy 授权、Handler 响应、Audit 记录。

## Monorepo 结构

```text
apps/
  spiffe-mtls-agent/      # 当前 SPIFFE mTLS 页面应用和真实 mTLS SDK 示例
app-registry.json         # 子应用目录、端口、生产 basePath、agent-build 快捷入口元数据
deploy/
  nginx/                  # 宿主 Nginx route snippets
  pm2/                    # PM2 runtime definition
scripts/list-apps.mjs     # registry inspection helper
```

新增子应用约定：

1. 新建 `apps/<app-id>`，应用自己持有源码、测试、文档和启动脚本。
2. 在 `app-registry.json` 增加 `workspace`、`deploy.basePath`、`deploy.port`、`agentBuildShortcut`。
3. 在 `deploy/pm2` 增加进程，在 `deploy/nginx` 增加 `/agent-demo/<app>/` 路由。
4. 在 agent-build 读取同一类 shortcut 元数据，渲染统一入口。

## SPIFFE 应用

文档入口：`apps/spiffe-mtls-agent/docs/README.md`

常用命令：

```bash
pnpm --filter @agent-demo/spiffe-mtls-agent typecheck
pnpm --filter @agent-demo/spiffe-mtls-agent test
pnpm --filter @agent-demo/spiffe-mtls-agent build
pnpm demo:spiffe
```

真实 SPIRE mTLS 命令仍在 `apps/spiffe-mtls-agent/docs/runbooks/spire-runtime-checklist.md`。

## 部署形态

目标服务器沿用 agent-build 所在 host 的路由模型：宿主 Nginx 负责路径分发，PM2 负责 Node app。当前应用公网路径为 `/agent-demo/spiffe/`，上游为 `127.0.0.1:5173`。

部署模板：

- `deploy/pm2/ecosystem.config.cjs`
- `deploy/nginx/agent-demo-spiffe.conf`
- `deploy/README.md`