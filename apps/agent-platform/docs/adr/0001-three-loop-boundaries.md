# ADR-0001：Workflow、Agent 与 Transaction 三循环

状态：Accepted
Owner：Architecture Owner
复核：每季度

## Decision

- Workflow Loop 由 Temporal 持久化，负责状态、重试、Signal、Timer、恢复和取消。
- Agent Loop 是概率执行边界，只负责 plan/execute/verify 的结构化候选输出。
- Transaction Loop 由 Tool Gateway、Approval 和 CommitService 组成；所有真实
  副作用必须进入 Transaction Loop。

Agent 不能成为业务事实源，也不能直接访问 CommitService、长期凭证或任意网络。
外部内容只能以 untrusted data 进入上下文。

## Consequences

边界增加组件数量，但获得可恢复、可审计、可重放和无重复副作用的控制。任何
绕开 Transaction Loop 的实现偏离都需要 ADR、Owner、替代控制和到期时间。
