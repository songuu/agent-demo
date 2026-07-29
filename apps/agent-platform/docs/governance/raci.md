# RACI

| 事项 | Accountable | Responsible | Consulted | Informed |
| --- | --- | --- | --- | --- |
| 架构基线 | Architecture Owner | Platform Lead | Security/SRE/Domain | 项目团队 |
| Tool 上线 | System Owner | Adapter Engineer | Security/Data Owner | Agent Team |
| Prompt/Model 发布 | AI Lead | Agent Engineer | QA/Domain/Security | SRE |
| Policy 变更 | Security Owner | Security Engineer | Platform/Business | 审计 |
| Critical Action | Business Risk Owner | Platform + System Owner | Security/Legal/SRE | 管理层 |
| 生产事故 | Incident Commander | On-call Teams | Security/Business/Provider | Stakeholders |

生产配置、Secret、Policy、Prompt、Tool Catalog、数据保留、SLO 和成本预算必须
各自拥有 Owner 与版本。
