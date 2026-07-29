# Tool / Action 风险矩阵

| Capability | Effect | Risk | Agent 可见 | 审批 | Commit Owner | 数据上限 |
| --- | --- | --- | --- | --- | --- | --- |
| knowledge.search | read | Low | 是 | 无 | 不适用 | internal |
| web.search | read | Low | 是 | 无 | 不适用 | public |
| artifact.create | prepare | Medium | 是 | 按 classification | Artifact Service | restricted |
| ticket.prepare | prepare | Medium | 是 | 1 名业务审批人 | commit-worker | confidential |
| email.prepare | prepare | High | 是，仅预览 | step-up + 1 名审批人 | commit-worker | confidential |
| payment.prepare | prepare | Critical | 默认禁用 | phishing-resistant + 双人 | 专用 commit-worker | restricted |
| commit_action | commit | Critical | 否 | 不适用 | CommitService only | 按 Action |

任何新增 Critical Action 必须由 Security、Business、SRE、Data/System Owner 共同
批准。发起人与审批人分离，payload hash 与审批绑定。
