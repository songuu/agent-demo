---
title: "Agent demo monorepo deploy integration"
type: sprint
status: complete
created: "2026-07-03"
updated: "2026-07-03"
checkpoints: 0
tasks_total: 6
tasks_completed: 6
tags: [sprint, monorepo, deployment, agent-demo]
aliases: ["agent-demo monorepo"]
invariants:
  - "SPIFFE app remains runnable by one page service"
  - "Production app routes must support a non-root BASE_PATH"
  - "agent-build shortcut model must allow future sub-apps, not only SPIFFE"
invariant_tests:
  - "pnpm typecheck"
  - "pnpm test"
  - "pnpm build"
deferred: []
deadcode_until: []
---

# Agent demo monorepo deploy integration

## Phase 1: 需求分析

Scope:

- 将当前 SPIFFE 相关实现迁移为 monorepo 中的 `apps/spiffe-mtls-agent` 子应用。
- 根仓库提供 workspace、app registry、部署模板，不再作为单一 SPIFFE 包。
- 发布到 `songuu/agent-demo`。
- 部署到 agent-build 同一服务器，由宿主 Nginx 以 `/agent-demo/spiffe/` 访问。
- 在 agent-build 增加快捷入口，并保留未来多子应用扩展模型。

Non-scope:

- 不把页面 demo 宣称为真实 SPIRE e2e。
- 不改 SPIFFE SDK 核心协议语义。
- 不把 agent-build 和 agent-demo 合并成一个仓库。

Success:

- `pnpm typecheck`、`pnpm test`、`pnpm build` 通过。
- 本地页面在 `/` 和 `/agent-demo/spiffe/` 都能访问。
- GitHub `songuu/agent-demo` 有提交。
- 服务器公开路由可访问页面、API、health、asset。
- agent-build 页面提供可扩展快捷入口。

Risks:

- Windows sandbox 拒绝删除迁移前未跟踪旧副本；提交时必须显式 stage monorepo 目标文件。
- 服务器现有 Nginx/PM2 路由不能破坏 `/agent-build/`、`/aicrew/` 等已上线路径。
- agent-build 入口必须做 registry/catalog，不写死单个 SPIFFE 链接。

## Phase 2: 技术方案

### 入场扫描 - Invariants 继承

| 子系统 | 上 sprint invariant | 本 sprint 如何保持 |
| --- | --- | --- |
| SPIFFE page demo | 一个服务展示完整过程 | app 内保留 `demo:web`，root 提供 `demo:spiffe` |
| 路由/部署 | host Nginx 做路由，PM2 做 runtime | 新增 PM2/Nginx 模板，不替换 agent-build 现有路径 |
| 文档边界 | 页面 demo 不替代真实 mTLS | README 和 docs 保留真实 SPIRE 命令边界 |

### 入场扫描 - 集成路径

| 改动点 | 触发动作 | 中间层 | 持久化 | 刷新后可见 |
| --- | --- | --- | --- | --- |
| SPIFFE app | 访问 `/agent-demo/spiffe/` | Nginx -> PM2 -> Node page server | 代码仓库 + release path | ✅ |
| agent-build shortcut | 点击快捷入口 | agent-build catalog/link | 静态站点构建产物 | ✅ |
| future sub-app | 增加 registry entry | registry -> deploy route -> shortcut | app-registry + docs | ✅ |

### 入场扫描 - 债务清单

| 来源 sprint | 议题 | 本 sprint 决策 | deadline |
| --- | --- | --- | --- |
| previous SPIFFE demo | 平铺包结构 | 本 sprint 迁移到 `apps/spiffe-mtls-agent` | 2026-07-03 |
| current deploy request | 多子应用入口模型 | 本 sprint 增加 registry 和 agent-build catalog 模式 | 2026-07-03 |

## Phase 3: Work

- [x] T1: monorepo workspace + app package + root registry。
- [x] T2: SPIFFE web demo 支持 `BASE_PATH`。
- [x] T3: 部署模板和架构规则。
- [x] T4: 本地验证 type/test/build/web routes。
- [x] T5: commit + push 到 `songuu/agent-demo`。
- [x] T6: 服务器部署 + agent-build 快捷入口 + public verification。

## Phase 4: Review

Current findings:

- P0: none after local type/test/build/http route verification.
- P1: Windows sandbox refused deleting old untracked flat-layout copies; they remain local-only and were not committed.

Verification so far:

- `pnpm install` -> pass.
- `pnpm typecheck` -> pass.
- `pnpm test` -> pass, 9 tests / 9 pass; sandbox run hit Node test runner `spawn EPERM`, escalated rerun passed.
- `pnpm build` -> pass.
- Local production server `node apps/spiffe-mtls-agent/dist/src/web/demo-server.js` with `BASE_PATH=/agent-demo/spiffe`:
  - `/` -> 200
  - `/agent-demo/spiffe/` -> 200
  - `/agent-demo/spiffe/api/demo` -> 200
  - `/agent-demo/spiffe/healthz` -> 200
  - `/agent-demo/spiffe/assets/spiffe-agent-mtls-complete-architecture.svg` -> 200
- Production deploy:
  - `pnpm deploy:prod -- --apply` -> pass.
  - Release path: `/opt/agent-demo/releases/20260703083507`.
  - PM2: `agent-demo-spiffe` online.
  - Public page: `https://songuu.top/agent-demo/spiffe/` -> 200.
  - Public health: `https://songuu.top/agent-demo/spiffe/healthz` -> 200.
  - Public asset: `https://songuu.top/agent-demo/spiffe/assets/spiffe-agent-mtls-complete-architecture.svg` -> 200.
- agent-build entry deploy:
  - `pnpm typecheck` -> pass.
  - `pnpm site:build` -> pass.
  - `pwsh scripts/deploy.ps1` -> pass.
  - Public catalog: `https://songuu.top/agent-build/docs/agent-apps` -> 200.
  - Production static output contains `agent-demo/spiffe` in home, catalog, navigation assets.

## Phase 5: Compound

Progress:

- agent-demo monorepo 已提交并推送到 `songuu/agent-demo` main。
- agent-build 快捷入口已提交并推送到 `songuu/agent` master。
- agent-demo 已部署到 agent-build 同一服务器，Nginx 以 `/agent-demo/spiffe/` 暴露。
- agent-build 已重新部署，提供 `应用入口` 导航和 `应用目录` 页面，后续子应用可按 catalog/registry 模式扩展。

Goal loop: iter n/a, until=n/a, goal-met=yes, decision=stop:met