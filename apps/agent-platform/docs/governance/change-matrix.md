# 变更验证矩阵

| 变更 | 风险 | 必需门禁 |
| --- | --- | --- |
| 代码 | 中-高 | unit/integration/E2E/security/replay/Canary |
| Model/Reasoning | 高 | full Eval、成本、延迟、灰度、回滚 |
| Prompt | 高 | Golden/Adversarial/schema/人工抽检 |
| Tool Schema/描述 | 高 | contract/tool selection/policy/security |
| Policy | Critical | OPA unit、权限矩阵、双人、shadow |
| Adapter | 高 | provider sandbox、幂等、UNKNOWN、回滚 |
| DB migration | 高 | 备份、锁、staging 数据量、前滚/回滚 |
| Infrastructure | 中-高 | IaC plan、策略扫描、容量、故障演练 |

一次 Canary 只改变模型、Prompt、Tool、Policy 中的一个变量。
