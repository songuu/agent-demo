---
title: "Agent demo GitHub workflow automation"
type: sprint
status: complete
created: "2026-07-03"
updated: "2026-07-03"
checkpoints: 0
tasks_total: 5
tasks_completed: 5
tags: [sprint, github-actions, deployment, agent-demo]
aliases: ["agent-demo workflow automation"]
invariants:
  - "GitHub workflow must reuse scripts/deploy-production.mjs for production mutation"
  - "agent-demo monorepo quality gates must keep typecheck/test/build/apps:list green"
  - "Production app route remains /agent-demo/spiffe/"
invariant_tests:
  - "pnpm typecheck"
  - "pnpm test"
  - "pnpm build"
  - "pnpm apps:list"
deferred: []
deadcode_until: []
---

# Agent demo GitHub workflow automation

## Phase 1: 需求分析

Scope:

- 参考 agent-build 的 `.github/workflows/agent-build-deploy.yml`，为 `agent-demo` 增加 GitHub Actions 自动化。
- push `main` 和手动 dispatch 都可触发生产部署。
- workflow 需要先跑质量门，再复用现有 `scripts/deploy-production.mjs --apply` 发布。
- README 记录 secrets 和触发方式。

Non-scope:

- 不在 workflow 中重写一套 Nginx/PM2/release 发布逻辑。
- 不改变当前生产路由 `/agent-demo/spiffe/`。
- 不新增多 app 动态部署系统，本 sprint 只覆盖现有 SPIFFE app 的自动发布入口。

Success:

- `.github/workflows/agent-demo-deploy.yml` 存在，结构对齐 agent-build workflow。
- workflow 包含 install、typecheck、test、build、apps:list、dry-run、自检、SSH、production deploy、production verify。
- secrets 文档明确。
- 本地 `pnpm typecheck/test/build/apps:list/deploy:prod` 验证通过。

Risks:

- GitHub runner 无生产 SSH secret 时 workflow 会在 secret 校验阶段失败，这是预期安全边界。
- 生产部署逻辑必须只调用现有 deploy script，避免两套发布逻辑漂移。
- 本地仍存在旧平铺未跟踪副本；提交必须显式 stage 目标文件。

## Phase 2: 技术方案

### 入场扫描 - Invariants 继承

| 子系统 | 上 sprint invariant | 本 sprint 如何保持 |
| --- | --- | --- |
| deploy | 生产发布通过 `scripts/deploy-production.mjs` 控制 Nginx/PM2/current | workflow 只调用 `pnpm deploy:prod -- --apply` |
| app route | SPIFFE app 支持 `BASE_PATH=/agent-demo/spiffe` | workflow build self-check 校验 snapshot basePath |
| monorepo | 根仓库保留 app registry 和 workspace 质量门 | workflow 跑 `pnpm apps:list` 与根脚本 |

### 入场扫描 - 集成路径

| 改动点 | 触发动作 | 中间层 | 持久化 | 刷新后可见 |
| --- | --- | --- | --- | --- |
| workflow deploy | push main / dispatch | GitHub Actions -> SSH -> deploy script | GitHub workflow file + production release | yes |
| secrets contract | repo secrets | GitHub Actions env | GitHub repository secrets | yes, missing secrets fail fast |
| docs | README | user setup path | repo markdown | yes |

### 入场扫描 - 债务清单

| 来源 sprint | 议题 | 本 sprint 决策 | deadline |
| --- | --- | --- | --- |
| agent-demo monorepo deploy | 手动生产部署 | 本 sprint 增加 GitHub Actions 自动部署 | 2026-07-03 |

## Phase 3: Work

- [x] T1: 新增 GitHub Actions deploy workflow。
- [x] T2: README 增加 workflow/secrets 使用说明。
- [x] T3: architecture rule 记录 CI/CD 发布边界。
- [x] T4: 本地 quality gates + dry-run 验证。
- [x] T5: review、commit、push。

## Phase 4: Review

Current findings:

- P0: none.
- P1: none.
- P2: GitHub workflow 的真实生产执行依赖仓库 secret `AGENT_DEMO_SSH_PRIVATE_KEY`；secret 已配置，值不写入仓库或日志。

Verification:

- `pnpm typecheck` -> pass.
- `pnpm test` -> sandbox hit `spawn EPERM`; escalated rerun pass, 9/9.
- `pnpm build` -> pass.
- `pnpm apps:list` -> pass.
- `pnpm deploy:prod -- --deploy-host root@47.253.230.197 --domain songuu.top --repository-url https://github.com/songuu/agent-demo.git --branch main` -> pass, dry-run only, no server mutation.
- workflow snapshot check command -> pass, `snapshot-ok=8`.
- `git diff --check` -> pass.
- `gh run list --repo songuu/agent-demo --limit 5` -> run `28649539442` triggered by push and failed fast at `Validate required secrets` because `AGENT_DEMO_SSH_PRIVATE_KEY` is not configured.
- `gh secret list --repo songuu/agent-demo` -> `AGENT_DEMO_SSH_PRIVATE_KEY`, `AGENT_DEMO_DEPLOY_HOST`, `AGENT_DEMO_DEPLOY_USER`, `AGENT_DEMO_DOMAIN` exist.
- New deploy key fingerprint -> `SHA256:Pjc6mNZEL3bLmzEWFnOIINZ6dewkZYZKSRhGx/GKjc8`.
- New deploy key SSH check -> `ok`.

## Phase 5: Compound

Learnings:

- agent-demo production automation should call the existing deploy script instead of duplicating release, Nginx, and PM2 logic in YAML.
- secret contract stays minimal: required SSH private key, optional host/user/domain defaults.

Goal loop: iter n/a, until=n/a, goal-met=yes, decision=stop:met