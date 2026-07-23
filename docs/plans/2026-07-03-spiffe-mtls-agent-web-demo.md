---
title: "SPIFFE mTLS Agent 页面版 Demo"
type: sprint
status: completed
created: "2026-07-03"
updated: "2026-07-03"
checkpoints: 0
tasks_total: 4
tasks_completed: 4
tags: [sprint, web-demo, architecture, spiffe, mtls]
aliases: ["SPIFFE Agent web demo"]
goal: "通过启动一个服务，直接在页面看到整个 SPIFFE mTLS Agent 架构过程和最小实现"
goal_max_iter: 3
goal_until: ""
goal_iteration: 0
goal_status: met
invariants:
  - "页面 demo 必须明确区分可视化学习和真实 SPIRE mTLS e2e"
  - "页面必须覆盖成功路径和安全失败路径"
  - "页面服务必须能通过一个命令启动"
invariant_tests:
  - "git diff --check"
  - "pnpm typecheck"
  - "pnpm test"
deferred:
  - sprint: "next"
    item: "用 Playwright 做页面截图回归"
    deadline: "2026-07-10"
    reason: "当前先用 HTTP/API/HTML 测试验证服务可用"
---

# Phase 1: Think

## Scope

- 新增一个本地 Web 服务，启动后直接通过页面观看 SPIFFE mTLS Agent 通信全过程。
- 页面展示成功路径、失败路径、代码映射、启动命令、完整架构图。
- 服务不依赖真实 SPIRE，作为学习可视化；真实 mTLS 路径继续保留 server/client 命令。

## Non-scope

- 不做真实 SPIRE e2e fixture。
- 不引入 React/Vite/Express 等额外依赖。
- 不把页面 demo 伪装成真实 TLS 握手结果。

## Success

- `pnpm demo:web` 可启动页面服务。
- `/`、`/api/demo`、`/healthz`、架构图 asset 可访问。
- 页面模型覆盖 register、SVID、mTLS 双侧校验、policy、handler、audit。
- 测试覆盖页面模型、HTML 渲染和 HTTP 服务。

# Phase 2: Plan

## 入场扫描 - Invariants 继承

| 子系统 | 上 sprint invariant | 本 sprint 如何保持 |
| --- | --- | --- |
| SPIFFE mTLS | 证书链 + SPIFFE URI SAN 双校验 | 页面步骤包含 client-checks-server / server-checks-client |
| Agent 授权 | handler 前统一授权 | 页面步骤包含 authorize，失败路径 policy-deny 阻断 handler |
| 文档边界 | 本地逻辑验证 != 真实 mTLS e2e | README 和教程说明页面服务是可视化学习 |

## 入场扫描 - 集成路径

| 改动点 | 触发动作 | 中间层 | 持久化 | 刷新后可见 |
| --- | --- | --- | --- | --- |
| 页面服务 | `pnpm demo:web` | Node http -> render page | 源码文件 | ✅ |
| API 模型 | `GET /api/demo` | demo-model snapshot | 源码文件 | ✅ |
| 架构图片 | 页面 `<img>` | `/assets/*.svg` allow-list | docs/architecture | ✅ |

## 入场扫描 - 债务清单

| 来源 sprint | 议题 | 本 sprint 决策 | deadline |
| --- | --- | --- | --- |
| 当前 | 页面截图回归 | 推迟；本轮先用 HTTP/HTML/API 测试 | 2026-07-10 |

## 任务拆解

- [x] T1: 新增 `src/web/demo-model.ts`。
- [x] T2: 新增 `src/web/demo-page.ts` 和 `src/web/demo-server.ts`。
- [x] T3: 新增 `demo:web` / `start:web` 脚本和 Web demo 测试。
- [x] T4: 更新 README / 教程 / 规则，并验证服务。

# Phase 3: Work

## 变更日志

- 新增原生 Node HTTP 页面服务，无新增依赖。
- 页面可播放成功路径，演示 3 条失败路径：server ID mismatch、policy deny、socket missing。
- `/api/demo` 暴露同一份架构过程模型，便于后续替换为真实事件源。
- `/assets/*` 只允许访问架构图 allow-list，避免任意文件读取。

# Phase 4: Review

## 视角 1 - 架构

通过。模型、渲染、HTTP 服务分层，后续可把 mock snapshot 替换为真实 runtime event stream。

## 视角 2 - 安全

通过。静态 asset 走 allow-list；文档明确页面 demo 不替代真实 SPIRE e2e。

## 视角 3 - 可用性

通过。一个命令启动页面，页面内有播放、重置、失败路径、命令区和代码层映射。

## 视角 4 - 代码质量

通过。无新增外部依赖，测试覆盖模型、HTML、HTTP endpoint。

## 视角 5 - 测试覆盖

通过。`pnpm typecheck`、`pnpm test` 覆盖新增代码；服务启动后用 HTTP 验证。

## 视角 6 - 集成连续性

通过。README、教程、docs index 均有页面 demo 入口；原真实 SPIRE server/client 命令保留。

# Phase 5: Compound

## 经验

- “架构 demo”最好同时有静态图和可交互页面：静态图负责全局结构，页面负责过程理解。
- 页面 demo 的模型数据独立于 HTML，有利于测试，也方便未来替换成真实事件流。
- 对安全架构 demo，失败路径必须一等展示，否则初学者只会记住 happy path。

## 验证

- `git diff --check` -> pass。
- `pnpm typecheck` -> pass。
- `pnpm test` -> pass，8 tests / 8 pass；沙箱内 Node test runner `spawn EPERM`，沙箱外重跑通过。
- 页面服务启动 -> pass。
- HTTP check `/`, `/api/demo`, `/healthz`, `/assets/spiffe-agent-mtls-complete-architecture.svg` -> pass。

## Goal loop

Goal loop: iter 0/3, until=n/a, goal-met=yes, decision=stop:met