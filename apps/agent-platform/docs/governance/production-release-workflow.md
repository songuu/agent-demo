# Agent Platform 生产发布工作流

唯一生产入口是
`.github/workflows/agent-platform-release.yml`。它执行
`quality → build_image → staging → production_canary → production`，并把
`build_image.image_digest` 作为后续环境唯一允许的镜像身份。production 不得重建、
按 tag 部署或覆盖 digest。

## 必须先配置的外部系统

工作流不会创建虚假的集群、流量或审批证据。运行前必须配置：

1. `agent-platform-staging`、`agent-platform-production-canary` 和
   `agent-platform-production` GitHub Environments。三个环境必须只允许
   `agent-platform-v*` release tag；production 还必须启用 Required reviewers、禁止发起人自审。
   仓库级 `main` 必须由 branch protection/ruleset 独立保护。
2. staging/production 各自的短期 kubeconfig、环境 Helm values 和 release smoke
   token。业务密码与模型密钥只存在于集群 Secret/Secret Manager，不能放入
   workflow 或 Helm values。
3. 一个 provider-specific progressive delivery controller，例如受管 rollout
   controller、service-mesh traffic controller 或同等系统。它必须消费
   `release-request.json` 中的 exact SHA/digest，执行 shadow、internal、1%、10%、
   50% 阶段，应用自动回滚与停止条件，并在受保护 HTTPS 端点发布证据。CI 不通过
   sleep、静态 JSON 或自签声明模拟观察窗口。
4. 独立审批系统。它必须通过短期 bearer token 暴露绑定
   `release_id/git_sha/image_digest` 的审批 bundle；Security、Business、SRE、
   Data/System Owner 必须是不同 actor，并提供 WebAuthn/FIDO2/PIV 等抗钓鱼认证
   时间与不可变 HTTPS evidence URI。
5. production Artifact API 与 final/staging 独立对象桶。final 桶必须启用版本、KMS、
   Public Access Block 和逐对象 COMPLIANCE Object Lock；`release-evidence` 与
   `release-evidence-component` 的 API metadata、对象保留期和 expiry 都不得少于
   365 天。`AGENT_PLATFORM_EVIDENCE_PUBLISH_TOKEN` 必须是单次运行短期凭据，只授予
   `artifact:write`、`artifact:read`、`artifact:evidence:write` 和 restricted
   data scope，并绑定当前 tenant。缺少任一回读条件时发布失败关闭。
6. provider-specific foundation evidence service。它必须从不可变
   `https://.../sha256:<digest>` URI 提供 canonical JSON attestation 与 Sigstore bundle，
   内容绑定当前 release/Git/image、Terraform `1.9.8`、真实 AWS/GCP/Azure resource IDs、
   regions、apply + cloud readback 或只读 cloud API readback、独立审批和所有关键控制。
   mock plan、`resource://` 占位符或 CI 自签声明不能替代真实云回读。

## GitHub 控制面发布预检

release tag 进入依赖安装、构建或环境 job 前，quality job 必须运行
`deploy/ci/validate_external_release_preflight.py`。声明式真值是
`deploy/ci/external-release-preflight.json`；它与工作流中每个 Environment 实际引用的
variables/secrets 集合由测试做精确相等校验，禁止只维护一份过期的人工清单。

仓库必须先安装一个仅限当前仓库的只读 GitHub App，并配置仓库级 variable
`AGENT_PLATFORM_PREFLIGHT_APP_CLIENT_ID` 与仓库级 secret
`AGENT_PLATFORM_PREFLIGHT_APP_PRIVATE_KEY`。工作流只为预检申请 `Actions: read`、
`Administration: read` 和 `Environments: read`，生成短期 installation token；
action 的 post step 会撤销 token。预检只读取 Environment、部署 branch/tag policy、
main branch protection/ruleset 以及 Variable/Secret metadata。Environment variables
列表 API 的响应可能包含 value；collector 收到响应后立即只保留 name，不把原始 payload、
Variable value 或 Secret value 写入 snapshot、日志或报告。Secret metadata API 本身不返回
Secret value。API URL 还必须由 `GITHUB_SERVER_URL` 推导，跨源重定向被拒绝。App 私钥必须
由仓库管理员轮换，不能复制到 Environment 或应用配置。

预检失败关闭验证：

- 仓库身份、默认分支 `main` 与当前 `agent-platform-v*` release tag；
- `main` 由 classic main branch protection/ruleset 或 active applicable ruleset
  强制至少一次 PR approval，并精确要求 strict status context
  `Quality, policy, deployment, and offline eval gates`，且绑定 GitHub Actions App
  `integration_id=15368`，不能允许任意写权限 actor 伪造同名 status；
- classic protection 必须启用 `enforce_admins`，并显式证明 users、teams、apps 三类
  pull-request bypass allowance 都为空；ruleset 的 `bypass_actors` 也必须在 API 响应中
  显式可见且为空。只读 API 未返回该字段时属于未知项并失败关闭，绝不能把缺失解释为空；
- 三个 GitHub Environment 均已显式创建，且所需 Variable 与 Secret metadata 名称完整；
- 三个 Environment 均启用 Selected branches and tags，并且只允许
  `type=tag,name=agent-platform-v*`，不允许额外的 `*` 或 branch pattern；
- production 至少有一个 Required reviewer，并启用禁止发起人自审。

Environment 的 tag policy 与 `main` 保护是两个独立控制：发布 job 由签名 annotated tag
触发，因此不能用 “Protected branches only” 代替 tag policy；`main` 的合并保护由仓库级
branch protection/ruleset 单独验证。成功或治理缺项时，机器报告写入
`.artifacts/external-release-preflight.json` 并上传；API、权限、认证或响应格式异常返回
operational failure，缺少治理项返回 blocked，二者都阻断后续构建与发布；该报告保留
365 天。

上述 `require_no_bypass` 只验证 GitHub API-visible 的 classic admin/allowance 与 ruleset
bypass 配置，不等价于组织级“任何 actor 都无法绕过”。classic branch protection payload
不会枚举 custom repository role 的 bypass 权限；仓库管理员必须在发布前独立审计角色授权，
并把结果写入受信、签名且可回读的治理证据。没有这项外部证据时，不得把预检 PASS 宣称为
全局零绕过证明。

## GitHub 环境配置

| Environment | 用途 | 必需配置 |
| --- | --- | --- |
| `agent-platform-staging` | exact digest Helm `--atomic`、read-only smoke、live eval、外部人工抽检 | `AGENT_PLATFORM_STAGING_*` secrets；staging/review HTTPS URLs |
| `agent-platform-production-canary` | 读取外部 controller 已部署的同一 digest 与完整 canary evidence | `AGENT_PLATFORM_CANARY_*` secrets/variables |
| `agent-platform-production` | 独立控制审批 + foundation attestation + 人工 deployment gate + 同 digest Helm + post-release readback | Required reviewers；`AGENT_PLATFORM_PRODUCTION_*`、内容寻址 `AGENT_PLATFORM_RELEASE_APPROVALS_URI`、`AGENT_PLATFORM_RELEASE_APPROVALS_SIGNER_IDENTITY`、`AGENT_PLATFORM_RELEASE_APPROVALS_SIGNER_ISSUER`、短期 `AGENT_PLATFORM_RELEASE_APPROVALS_BEARER_TOKEN`、`AGENT_PLATFORM_FOUNDATION_ATTESTATION_*` 与 `AGENT_PLATFORM_EVIDENCE_PUBLISH_TOKEN` |

`*_KUBECONFIG_B64`、release token、外部 evidence bearer token 和
`AGENT_PLATFORM_EVIDENCE_PUBLISH_TOKEN` 都应由 OIDC/Secret Broker 按单次运行签发，
设置最短可行 TTL。长期云密钥、静态 registry 密码或业务系统 credential 不得进入
GitHub Secrets。证据发布 token 不能复用业务 release token，也不能包含 secret
分类或跨 tenant 数据权限。`AGENT_PLATFORM_FOUNDATION_ATTESTATION_BEARER_TOKEN`
同样必须是单次运行短期只读凭据；signer identity/issuer 必须配置为精确值，不能使用通配符。
审批服务同样只接受短期 bearer token；审批原文必须是无尾随换行且字符串采用 NFC 的 canonical JSON，
`AGENT_PLATFORM_RELEASE_APPROVALS_URI` 必须以 `/sha256:<64 hex>` 结尾，并由
Sigstore bundle 绑定精确的 `AGENT_PLATFORM_RELEASE_APPROVALS_SIGNER_IDENTITY` 与 issuer。

staging/production Environment 还必须分别配置三组观测端点与短期 token：
`AGENT_PLATFORM_GRAFANA_API_URL` / `AGENT_PLATFORM_GRAFANA_API_TOKEN`、
`AGENT_PLATFORM_ALERTMANAGER_API_URL` / `AGENT_PLATFORM_ALERTMANAGER_API_TOKEN`、
`AGENT_PLATFORM_ALERT_DELIVERY_RECEIPT_BASE_URL` /
`AGENT_PLATFORM_ALERT_DELIVERY_RECEIPT_TOKEN`。工作流用它们做六 dashboard runtime API
读回和真实 receiver delivery receipt 验证；权限、receipt API 契约与失败边界见
`docs/governance/observability-release-assets.md`。

## Exact-release 人工抽检证据

staging live gate 不接受预置审核 JSON。`AGENT_PLATFORM_STAGING_HUMAN_REVIEW_SERVICE_TOKEN`
是短期服务认证材料，`AGENT_PLATFORM_STAGING_HUMAN_REVIEW_SERVICE_URL` 必须是受保护
HTTPS 端点；静态 secret 只用于审核服务认证，不能承载可跨发布复用的审核结论。

live runner 先保存 `live-candidate-manifest.json` 与
`live-candidate-results.json`。前者绑定 `release_id`、Git SHA、image digest、suite、
offline results 和 baseline；后者保存本次 case_id、真实 run_id 与结果摘要。runner 对规范
JSON 计算 `candidate_manifest_sha256` 和 `candidate_results_sha256`，再向外部审核服务
提交 exact candidate 并真实轮询同源 HTTPS status URL；超时、重定向、跨源 URL 或非 2xx
状态全部失败关闭。

外部证据必须通过 `deploy/ci/human-review-evidence.schema.json` 和额外不变量校验：

- 绑定当前 release_id、candidate_manifest_sha256、candidate_results_sha256 和服务 request_id；
- 具有 50-100 个唯一 sample_id 和唯一 subject SHA-256，每项 case_id/run_id 都属于本次
  candidate results，且抽样维度覆盖 use_case、risk、dataset；
- 每个样本完整填写 E.4 的正确性、完整性、证据、不确定性、行动质量、表达六维 1–5 分；
- reviewer 身份、组织、WebAuthn/FIDO2/PIV/OIDC/SAML MFA subject 与认证时间可追溯；
- provenance 包含同源 HTTPS evidence URI、requested/completed/issued/expires 时间，证据在
  最大年龄内且未过期；所有样本 pass、整体 approved、major/critical finding 为零。

runner 将原始 `human-review-evidence.json` 与 candidate artifacts 一并上传，即使 gate 失败也
保留可诊断证据。任何样本不足、重复、rubric 缺失、case/run 漂移、旧 release/digest、过期
证据或重大问题都会阻断 staging，后续 canary/production 不会启动。

## 外部 canary evidence

controller 在
`${AGENT_PLATFORM_CANARY_EVIDENCE_BASE_URL}/${release_id}.json` 发布
`deploy/ci/canary-evidence.schema.json`。`validate_canary_evidence.py` 会 fail
closed 检查：

- release id、40 位 Git SHA 和 `sha256:` image digest 与 build job 完全一致；
- provider/controller 不是 demo、fixture 或自签测试实现；
- canary policy 中所有阶段按序完成，时间戳证明每阶段与总观察窗口达到下限；
- 所有停止条件均完整评估且为 clear，rollback ready，最终结果为 passed。

`100%` 是 production promotion 后的阶段，不包含在“发布前 canary 已完成”的
声明中；production job 完成 exact identity、依赖健康和 smoke readback 后才可
记录全量发布成功。

## Production foundation attestation

production 在 Helm 前下载 `AGENT_PLATFORM_FOUNDATION_ATTESTATION_URI` 与其
`.sigstore.json` bundle。`validate_foundation_attestation.py` 自行执行 `cosign verify-blob`，
并 fail closed 验证：

- source URI 末尾 digest 与 exact canonical signed bytes SHA-256 相等；signer identity/issuer
  与 Environment vars 精确相等；
- release_id、40 位 Git SHA、image digest 和 Terraform `1.9.8` 与本次 job 完全一致；
- execution 是已完成的 Terraform apply + provider readback，或明确 `read_only=true` 的 cloud
  API readback；plan、execution、resource-readback evidence 均为 digest-addressed URI；
- PostgreSQL HA/multi-zone/PITR/RPO/RTO/TLS/KMS、final/staging bucket 的独立 KMS/versioning/
  COMPLIANCE Object Lock、Temporal TLS/HA、signed fail-closed OPA、default-deny egress 和
  Secret Manager/Workload Identity/rotation/audit/JIT 全部为真；
- AWS ARN、GCP full resource name 或 Azure resource ID 与 provider/region 一致，不接受
  `resource://`、fixture、demo 或缺失 ID；基础 KMS keys 独立；
- Infrastructure Owner 与 Security/SRE 至少两名不同 actor 审批，所有时间戳在最大年龄内。

任何 URI/token/signer 输入缺失、签名失败、过期、错绑或关键控制为假都会在 Helm 前退出。
组件发布后，工作流还会用 governed Artifact 的真实回读 attestation 与 signature bundle
再执行一次 `cosign verify-blob`。本地 schema、mock Terraform 和测试只证明闸门逻辑，
没有真实云 attestation 时不得声明 production foundation 已验证。
## Operational gate 原始证据

`validate_operational_readiness.py` 不接受仅由 gate issuer 自报的 `status=passed` 和汇总
`checks`。除 capacity 继续使用完整六场景 `raw_capacity_report` 外，其余 11 个 required gate
都必须在签名 gate report 中绑定 `raw_evidence.uri` 与 `raw_evidence.sha256`。URI 必须是
同源 HTTPS，末端路径段精确等于完整 `sha256:<64-lowercase-hex>`，不得使用 digest substring、
可变 suffix、query 或 fragment。validator 在本地证据目录和生产 Bearer fetch 模式都会有界流式读取
原始 bytes（先检查 stat/Content-Length，但不单独信任它们）、重算 digest，使用 strict JSON
拒绝 `NaN/Infinity/-Infinity`，并以 finite-number 防御校验数值；随后校验 release ID、Git SHA、
image digest、目标环境、采集时间和 machine producer provenance。

非 capacity raw evidence 按 check 保存机器样本而不是 `passed` 标量。validator 使用仓库固定、
issuer 不可选择的 reducer 重新派生 hard predicate：布尔样本取全真、事件/历史/dashboard ID
去重计数、上限指标取最坏 `max`、下限指标取最坏 `min`，然后同时验证 policy threshold 与
signed gate report 的 observed 值一致。缺 gate、缺/多 measurement、未知 reducer、空或错类型
样本、重复计数 ID、过期/错绑、mutable/cross-origin URI 或 digest 漂移都会 fail closed。
validation receipt 输出每个 gate 的 raw URI/digest；最终 `release-evidence.json` 原样包含并由
schema/builder 再次校验完整 12 项及内容寻址关系。

该离线校验能复算 gate hard predicate 和证据绑定，但不会重新执行外部云 API、真实恢复演练、
红队攻击或生产告警投递；这些事实仍必须由授权的 machine collector 从对应系统产生 raw samples，
并由签名 gate report 对其 digest 负责。缺少真实外部采集时，不得把本地 fixture 解释为生产验证。

## 审批与最终证据
`release-approvals.schema.json` 和 `validate_release_approvals.py` 验证四类控制审批。
审批源必须包含 Security、Business、SRE、Data/System Owner 四个互不相同的 actor，
每个 actor 使用 WebAuthn/FIDO2/PIV。工作流先校验 URI 声明摘要与下载原始字节一致，
再用精确 OIDC identity/issuer 执行 `cosign verify-blob`；validator 绑定 canonical JSON、
source URI/digest、signature bundle digest、release/Git/image identity 和时效。
GitHub Environment review 是额外 deployment gate，不替代这些控制角色。production
job 会从 GitHub workflow run review-history API 回读真实 reviewer；无匹配
`agent-platform-production` 的 `approved` User 时立即失败。

production 必须先下载 quality job 上传的 external preflight report，并以当前
repository、release tag、Git SHA 和 release ID 重新执行离线身份与完整性校验。该复验位于
生产凭据读取和 Helm materialize/deploy 之前；缺失、畸形、身份不匹配或任一 check 非
passed 都失败关闭。复验输出仅保留已知安全字段；最终组件证据发布该净化回执，而不是
原始下载报告。

`scripts/build_release_evidence.py` 只接受完整 approvals bundle、回读后的 deployment
approval 和 `component-evidence-publication.json`，不再接受单个 `--approval-actor` 或
任意 GitHub run 页面片段 URL。production 先将下列 22 项作为 restricted
`release-evidence-component` 上传，再验证 malware-clean、release/git/image binding、
VersionId、retention policy、retain-until/expiry 和 digest-addressed 307 回读：

- SBOM、provenance；
- live eval、candidate manifest/results、外部 human review；
- canary、staging/production verification；
- signed production foundation attestation、Sigstore bundle 及 validation；
- operational readiness 及 validation；
- signed release approvals 原文、Sigstore bundle 及 validation；
- deployment approval、经 schema/validator 验证且包含 Grafana runtime readback 与
  immutable receiver receipt 的 production observability；
- external release preflight report。

已签名的 foundation、canary、release approvals 原文及其 Sigstore bundle 均按
`application/octet-stream` 原样发布，禁止 Artifact JSON sanitizer 重编码。组件回读后，
工作流再次使用已发布原文和 bundle 执行 `cosign verify-blob`。构建器还会逐字节核对 approvals 原文、bundle、validation
三个 SHA-256，再只从该已验证回执派生证据 URI。`release-evidence.json` 输出为 canonical JSON，
先做 detached SHA-256 与 keyless cosign 签名，再将 evidence、digest、signature bundle
以 `release-evidence` 发布。工作流随后重新下载三个真实对象，重算 digest，并对回读
evidence 再执行 `cosign verify-blob`；发布摘要以 digest-addressed Artifact URI 为主，
GitHub Artifact 只是 365 天副本。

只有 production post-release exact SHA/digest、依赖健康、只读 smoke、22 项组件回读、
最终对象签名复验全部成功，工作流才结束为成功。失败时按
`docs/runbooks/release-rollback.md` 回滚到签名 operational readiness 中明确批准的
previous Helm revision/Git/image/Tool Catalog。工作流在部署前读回该 revision 的
manifest 和四个 workload，禁止从 history 自动猜目标；Helm 写入步骤成功后，任何
rollout、observability、smoke、组件发布、最终签名或 readback 失败，都会以
`--no-hooks` 执行一次该目标并再次验证旧 release identity。回滚证据即使主发布失败
也保留 365 天；真实演练和不可变 incident 归档仍是外部完成项。
