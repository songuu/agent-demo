---
title: "SPIFFE mTLS Agent 新手图文完善"
type: sprint
status: completed
created: "2026-07-03"
updated: "2026-07-03"
checkpoints: 0
tasks_total: 4
tasks_completed: 4
tags: [sprint, documentation, architecture, spiffe, mtls]
aliases: ["SPIFFE Agent beginner docs"]
goal: "将 demo 更加完善，让初学这个架构的人可以更好上手，使用图文结合说明复杂架构"
goal_max_iter: 3
goal_until: ""
goal_iteration: 0
goal_status: met
invariants:
  - "新手文档必须区分本地逻辑验证和真实 SPIRE mTLS 验证"
  - "复杂架构必须有图片入口，不只依赖文字说明"
  - "身份验证和授权职责必须分开解释"
invariant_tests:
  - "git diff --check"
  - "pnpm typecheck"
  - "pnpm test"
deferred:
  - sprint: "next"
    item: "真实 SPIRE e2e 自动化测试 fixture"
    deadline: "2026-07-10"
    reason: "当前工作区没有可直接启动的 SPIRE Server/Agent 测试环境"
---

# Phase 1: Think

## Scope

- 把已有 SPIFFE mTLS demo 从“能看懂代码的人可用”提升为“初学者可按图文路径上手”。
- 补全学习地图、握手时序、SVID 轮换、代码地图。
- README 做入口页，长教程放入 docs。
- 保持真实验证边界：没有 SPIRE 时只证明本地逻辑，不宣称 mTLS e2e。

## Non-scope

- 不部署真实 SPIRE Server/Agent。
- 不把 demo 改成 mock TLS 假成功。
- 不引入外部图片渲染工具作为运行依赖。

## Success

- 初学者能从 README 找到学习顺序。
- 教程能解释核心名词、运行步骤、失败定位、扩展方向。
- 文档包含可打开的 SVG 图片。
- 验证命令和文档边界清晰。

# Phase 2: Plan

## 入场扫描 - Invariants 继承

| 子系统 | 上 sprint invariant | 本 sprint 如何保持 |
| --- | --- | --- |
| SPIFFE mTLS | 证书链 + SPIFFE URI SAN 双校验 | 教程和时序图明确 client/server 双侧校验 |
| Agent 授权 | handler 前统一授权 | 新手教程把 TLS 认证和 Policy 授权分开解释 |
| 身份材料 | SVID/key 不落长期配置 | SVID 轮换图说明 Workload API stream 和内存更新 |

## 入场扫描 - 集成路径

| 改动点 | 触发动作 | 中间层 | 持久化 | 刷新后可见 |
| --- | --- | --- | --- | --- |
| README 学习入口 | 打开 README | docs links | markdown 文件 | ✅ |
| 教程图片 | 打开教程 | SVG 图片 | docs/architecture | ✅ |
| SPIRE runbook | 准备真实环境 | deploy registration + runtime env | markdown 文件 | ✅ |

## 入场扫描 - 债务清单

| 来源 sprint | 议题 | 本 sprint 决策 | deadline |
| --- | --- | --- | --- |
| 上轮 | 真实 SPIRE e2e | 继续推迟，增加 runbook 降低接入成本 | 2026-07-10 |

## 任务拆解

- [x] T1: 新增学习地图、握手时序、SVID 轮换、代码地图 SVG。
- [x] T2: 新增 `docs/tutorials/spiffe-mtls-agent-beginner-guide.md`。
- [x] T3: 新增 `docs/runbooks/spire-runtime-checklist.md` 和 `docs/README.md`。
- [x] T4: 串 README / architecture / registration 入口并完成验证。

# Phase 3: Work

## 变更日志

- 新增图文教程，覆盖名词解释、运行路径、失败定位、安全检查、扩展方向。
- 新增 4 张精确 SVG 图片：学习地图、握手时序、SVID 轮换、代码地图。
- 新增 SPIRE 运行清单，明确真实 mTLS 验证前提。
- 更新 README 为学习入口页。

# Phase 4: Review

## 视角 1 - 架构

通过。README、教程、架构文档、runbook 形成从概念到运行的闭环。

## 视角 2 - 安全

通过。文档明确区分 TLS 身份验证和 Policy 授权；没有把本地单元测试说成真实 mTLS e2e。

## 视角 3 - 可上手性

通过。新增学习地图、握手时序、SVID 轮换、代码地图，并给出推荐阅读顺序和失败定位表。

## 视角 4 - 代码质量

通过。本轮不改运行时代码；文档链接和图片文件独立可维护。

## 视角 5 - 测试覆盖

通过。执行文档链接检查、SVG XML 检查、`git diff --check`、`pnpm typecheck`、`pnpm test`。

## 视角 6 - 集成连续性

通过。新增文档均从 README 和 docs index 可达；SPIRE registration 文档链接到 runbook。

# Phase 5: Compound

## 经验

- SPIFFE/mTLS 这类复杂安全架构，初学者需要“概念图 -> 握手图 -> 生命周期图 -> 代码地图”的递进，不适合只给全景图。
- 文档必须把“不接 SPIRE 的本地验证”和“接真实 SPIRE 的 e2e 验证”分开，否则容易把单元测试误读成 mTLS 成功。
- 安全 demo 的失败用例也是教学材料：target ID 错、caller 未授权、socket 不可用都应该被解释为边界生效。

## 验证

- SVG XML parse -> pass，5 个 SVG 全部 OK。
- Markdown 本地链接检查 -> pass。
- `git diff --check` -> pass。
- `pnpm typecheck` -> pass。
- `pnpm test` -> pass，5 tests / 5 pass；沙箱内曾因 Node test runner `spawn EPERM` 失败，沙箱外重跑通过。

## Goal loop

Goal loop: iter 0/3, until=n/a, goal-met=yes, decision=stop:met