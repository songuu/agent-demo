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

## 生产部署脚本

默认 dry-run，不改服务器：

```bash
pnpm deploy:prod
```

真正部署必须显式授权执行：

```bash
pnpm deploy:prod -- --apply
```

脚本会读取 `app-registry.json`，创建 `/opt/agent-demo/releases/<timestamp>`，构建 `apps/spiffe-mtls-agent`，切换 `/opt/agent-demo/current`，启动 PM2 `agent-demo-spiffe`，并把宿主 Nginx 接到 `/agent-demo/spiffe/`。默认只打印远端脚本，不会写服务器。

## GitHub Actions 自动部署

`.github/workflows/agent-demo-deploy.yml` 参考 agent-build 的生产 workflow：push 到 `main` 或手动 `workflow_dispatch` 后，先执行 `pnpm install --frozen-lockfile`、`pnpm typecheck`、`pnpm test`、`pnpm build`、`pnpm apps:list`，再复用 `scripts/deploy-production.mjs --apply` 发布生产。

必需 secret：

- `AGENT_DEMO_SSH_PRIVATE_KEY`：连接生产服务器的 SSH 私钥。

可选 secret：

- `AGENT_DEMO_DEPLOY_HOST`，默认 `47.253.230.197`。
- `AGENT_DEMO_DEPLOY_USER`，默认 `root`。
- `AGENT_DEMO_DOMAIN`，默认 `songuu.top`。

workflow 不复制远端发布逻辑；生产变更仍统一收敛在 `scripts/deploy-production.mjs`。