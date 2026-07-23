---
title: "SPIFFE mTLS Agent 通信架构重设计"
type: sprint
status: completed
created: "2026-07-03"
updated: "2026-07-03"
checkpoints: 0
tasks_total: 5
tasks_completed: 5
tags: [sprint, architecture, spiffe, mtls, agent]
aliases: ["SPIFFE Agent mTLS"]
goal: "重新设计项目级架构：使用 SPIFFE SDK 建立 Agent 通信的 mTLS 双向认证方案，并尽量落到仓库文件中"
goal_max_iter: 3
goal_until: ""
goal_iteration: 0
goal_status: met
invariants:
  - "Agent 通信必须同时校验证书链和 SPIFFE URI SAN"
  - "授权逻辑必须位于业务 handler 之前"
  - "SVID/private key 不写入长期项目配置"
invariant_tests:
  - "pnpm typecheck"
  - "pnpm test"
deferred:
  - sprint: "next"
    item: "接入真实 SPIRE e2e 测试环境"
    deadline: "2026-07-10"
    reason: "当前仓库没有 SPIRE server/agent 环境"
---

# Phase 1: Think

## Scope

- 把单文件 SPIFFE mTLS demo 重设计为项目级架构。
- 明确 SPIRE / Workload API / SDK adapter / Policy / Transport / Runtime 边界。
- 保留可运行入口，便于后续接真实 SPIRE 环境。

## Non-scope

- 不部署真实 SPIRE Server/Agent。
- 不引入 OPA/Cedar 等外部 policy engine。
- 不为所有语言实现 SDK；TypeScript 项目先落 Workload API adapter。

## Success

- 仓库有项目级目录结构和架构文档。
- Client 侧有 expected server SPIFFE ID 校验。
- Server 侧有 client certificate + SPIFFE ID authorization。
- 证书轮换能更新 server secure context。

# Phase 2: Plan

## 入场扫描 - Invariants 继承

| 子系统 | 上 sprint invariant | 本 sprint 如何保持 |
| --- | --- | --- |
| SPIFFE mTLS | 无历史 sprint | 新增 invariant：证书链 + SPIFFE URI SAN 双校验 |
| Agent 授权 | 无历史 sprint | 新增 invariant：handler 前统一授权 |
| 身份材料 | 无历史 sprint | 新增 invariant：SVID/key 不落长期配置 |

## 入场扫描 - 集成路径

| 改动点 | 触发动作 | 中间层 | 持久化 | 刷新后可见 |
| --- | --- | --- | --- | --- |
| Agent server | `pnpm start:server` | Runtime -> IdentitySource -> Transport | 无长期 secret | 进程重启后重新取 SVID |
| Agent client | `pnpm start:client` | Runtime -> IdentitySource -> mTLS Client | 无长期 secret | 进程重启后重新取 SVID |
| Policy | server request | Transport -> PeerAuthorizer -> handler | 当前静态配置 | 重启后按 env/config 生效 |

## 入场扫描 - 债务清单

| 来源 sprint | 议题 | 本 sprint 决策 | deadline |
| --- | --- | --- | --- |
| 当前 | 真实 SPIRE e2e | 推迟到下一 sprint | 2026-07-10 |

## 任务拆解

- [x] T1: 拆分单文件 demo 为 `src/spiffe` / `src/policy` / `src/transport` / `src/runtime`。
- [x] T2: 添加项目级 `README.md`、`package.json`、`tsconfig.json`。
- [x] T3: 写 `docs/architecture/spiffe-agent-mtls.md`。
- [x] T4: 写 SPIRE registration 示例和 policy 示例。
- [x] T5: 补纯逻辑单元测试，执行可用性验证。

# Phase 3: Work

## 变更日志

- 重构 `spiffe-mtls-agent.ts` 为兼容入口。
- 新增 IdentitySource：`src/spiffe/workload-x509-source.ts`。
- 新增 server/client transport：`src/transport/`。
- 新增 policy 层：`src/policy/peer-policy.ts`。
- 新增 runtime 配置与 CLI：`src/runtime/`、`src/cli.ts`。
- 新增架构文档、SPIRE 注册示例、policy 示例。

# Phase 4: Review

## 视角 1 - 架构

通过。TLS、身份、授权、运行时配置已分层。

## 视角 2 - 安全

通过。Client 校验 expected server SPIFFE ID；Server 统一授权 client SPIFFE ID；不依赖 DNS 作为身份。

## 视角 3 - 性能

通过。SVID 通过 stream 缓存；HTTPS agent keep-alive；server secure context 热更新。

## 视角 4 - 代码质量

通过。错误携带 context；模块边界清晰；单文件入口兼容。

## 视角 5 - 测试覆盖

部分通过。新增纯逻辑测试；真实 SPIRE e2e 因环境缺失推迟。

## 视角 6 - 集成连续性

通过。新建 API/entrypoint 被 README 和 CLI 使用；遗留单文件不再承载业务实现。

# Phase 5: Compound

## 经验

- SPIFFE mTLS 项目化时，最重要边界是 IdentitySource 和 PeerAuthorizer，而不是 TLS option 本身。
- Workload API stream 是证书生命周期中心；业务代码不应直接持有长期证书路径。
- SPIRE registration 解决“谁能拿 SVID”，项目 policy 解决“拿到 SVID 后能做什么”。

## 验证

- `pnpm install` -> pass（已 approve `esbuild` / `protobufjs` build scripts）。
- `pnpm typecheck` -> pass。
- `pnpm test` -> pass，5 tests / 5 pass。
- sandbox 内直接跑 `pnpm` 曾触发 `_tmp_* unlink EPERM`；外部执行验证通过，临时文件已清理。
## Goal loop

Goal loop: iter 0/3, until=n/a, goal-met=yes, decision=stop:met