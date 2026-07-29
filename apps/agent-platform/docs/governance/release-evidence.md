# 发布证据包

每次 staging/prod 晋级必须保存：

- Git SHA、不可变 image digest、基础镜像 digest；
- SBOM、签名、provenance、依赖/镜像/IaC 扫描结果；
- Workflow code、SDK、model route、Prompt、Tool、Policy、Contract 版本；
- Alembic revision、备份/锁评估和 replay 结果；
- Golden/Edge/Adversarial/Incident Eval 与人工抽检；
- exact live candidate manifest/results 及其规范 JSON SHA-256；
- 外部 HTTPS 人工审核原始证据：50–100 个唯一样本、case/run 绑定、E.4 六维 rubric、
  reviewer/auth/provenance/freshness 和零 major/critical finding；
- staging E2E、故障注入、红队和 SLO/成本/延迟结果；
- 12 个 operational gate 的同源 HTTPS 内容寻址 raw evidence URI/SHA-256 与 validation receipt；
  validator 必须读取真实 bytes、校验 release/Git/image/environment/freshness，并用固定 reducer
  从机器样本复算 hard predicates；
- operational readiness 原文和 validation receipt 必须分别以本地原始 bytes 计算 SHA-256，
  与发布回执中的对应 asset 精确匹配；最终 release evidence 只记录发布后的
  digest-addressed `content_uri`，并同时保存 validation URI 与 SHA-256，形成可追溯双绑定；
- production observability：六个 Grafana runtime API 回读、release-bound synthetic alert、
  Alertmanager API 回读、真实 receiver delivery 与 digest-addressed immutable receipt；
- production foundation attestation、Sigstore bundle 与 validation：绑定 release/git/image、
  Terraform 版本、真实 provider resource IDs/regions、apply/read-only readback、HA/PITR/KMS/
  Object Lock/Temporal TLS/OPA/egress/secrets 和独立审批；
- Security、Business、SRE、Data/System Owner approvals；
- Canary 对象、观察窗口、成功/停止条件和回滚 Owner。

证据遵循 `deploy/ci/release-evidence.schema.json`。17 项组件先作为 restricted、
malware-clean、release/git/image-bound 的 `release-evidence-component` 存入 final
Artifact；每项回执必须包含 SHA-256、VersionId、`release-evidence@1:immutable:>=365d`
策略、COMPLIANCE retain-until、expiry 和成功的 digest-addressed 内容回读。最终
canonical `release-evidence.json` 连同 detached digest、cosign bundle 再以
`release-evidence` 发布，并对真实回读字节重新验 hash/签名。GitHub Artifact 只作副本，
不能替代受治理 Artifact URI。只有存在完整且回读验证成功的证据包才能关闭发布。


根 CI 会上传
`.artifacts/agent-platform/offline-release-evals.json`，它只证明本地硬控制通过。
该文件中的 `full_release_ready=false` 和零人工复核样本不得被覆盖；模型质量、
生产基线、成本/延迟回归与 50–100 个真实高风险人工样本必须由有凭据的 live
quality gate 另行补齐。
