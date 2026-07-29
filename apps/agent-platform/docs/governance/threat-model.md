# Threat Model

| ID | 威胁 | 核心控制 |
| --- | --- | --- |
| T-01 | Prompt Injection | trust/taint、Context Builder、Gateway、Trajectory |
| T-02 | 权限升级 | immutable principal/data_scope、default deny、重授权 |
| T-03 | 跨租户泄露 | RLS、prefix、tenant-aware cache、隔离测试 |
| T-04 | 恶意/混淆 Tool/MCP | Registry/version/strict schema/allowlist |
| T-05 | 重复副作用 | PreparedAction、幂等、行锁、UNKNOWN lookup |
| T-06 | Sandbox 逃逸 | gVisor、rootless、read-only、deny egress、quota |
| T-07 | 目标漂移 | plan version、Trajectory Monitor、Kill Switch |
| T-08 | 数据投毒 | provenance、owner、version、trust、conflict detection |
| T-09 | 敏感 Trace 泄露 | minimization、redaction、classification、retention |
| T-10 | 供应链 | lockfile、SBOM、签名、扫描、Eval、Canary、回滚 |

Use Case 上线前必须完成数据流、Trust Boundary、Tool/Action、威胁 Owner、残余
风险与对应回归测试。Critical/High 残余风险必须有批准和到期。
