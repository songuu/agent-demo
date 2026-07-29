# 实施路线

1. 阶段 0：Use Case、数据/工具、Threat Model、Action Matrix、Eval Contract、
   容量与成本假设。
2. 阶段 1：只读 MVP，外部写全部 deny；API/DB/Temporal/Gateway/Artifact/
   Prompt Registry/Trace/Eval 完成。
3. 阶段 2：受控 Action；Preview/Approval/Commit/Receipt/Verify/Compensate，
   完成 UNKNOWN、重复、过期和补偿演练。
4. 阶段 3：仅为天然并行或独立验证增加子 Agent；加入 Compaction、Trajectory、
   Tool Search/MCP/Sandbox 和质量运营。

任何里程碑不得通过跳过安全、Eval、恢复和审计压缩 Critical Action 上线时间。
