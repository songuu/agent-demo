# 数据保护矩阵

| 分类 | 允许模型 | 工具 | 存储 | 日志/Trace | 下载 |
| --- | --- | --- | --- | --- | --- |
| public | 批准 allowlist | read/prepare | 标准加密 | 可记录摘要/hash | 普通授权 |
| internal | 企业批准项目 | data_scope 工具 | tenant prefix | tenant tokenized | 短时 URL |
| confidential | 专用项目/地域 | 明确 allowlist | KMS + 版本 | 默认无正文 | user+tenant+purpose |
| restricted | 显式业务批准 | 最小工具集 | tenant/domain key | hash/ref only | 单次短时 URL |
| secret | 默认不送模型 | 专用服务 | 专用 KMS | 禁止正文 | 默认禁止 |

模型前执行字段最小化和令牌化。DB、队列、对象、备份传输与静态加密。Artifact
上传必须 MIME 校验、恶意软件扫描、解压限额、净化、hash。保留例外需要 Owner、
法律依据和到期时间。
