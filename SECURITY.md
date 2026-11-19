# 安全策略 / Security Policy

本策略适用于 openGauss oGRAC 仓库中的多主关系型数据库及其相关代码。疑似安全漏洞请通过 openGauss 社区安全小组（SIG Security）的官方渠道报告。

适用问题包括认证绕过、权限提升、敏感信息泄露、越权访问、内存破坏、SQL 注入，以及可被利用破坏数据完整性或导致集群服务不可用的缺陷。

## 报告安全漏洞 / Reporting a Vulnerability

请发送邮件至 [securities@opengauss.org](mailto:securities@opengauss.org)，并在主题中注明 `openGauss oGRAC` 和受影响的插件名称。请勿在公开 Issue、Pull Request 或讨论区提交尚未披露漏洞的利用细节。

报告中建议包含：

* 受影响的插件、openGauss oGRAC 版本，以及分支、版本或提交号。
* 操作系统、部署形态（单机/多节点）、相关配置、触发条件和所需权限。
* 潜在安全影响，以及在隔离测试环境中的最小复现步骤或概念验证。
* 已有 CVE 编号、修复建议和便于后续沟通的联系方式（如有）。

请先移除密码、访问令牌、个人信息和生产数据。涉及敏感技术细节时，建议使用[官方漏洞管理页面](https://opengauss.org/zh/vulnerability-management/)提供的 PGP 公钥加密邮件。

## 支持范围 / Supported Versions

安全响应范围以 [openGauss 官方漏洞管理政策](https://opengauss.org/zh/vulnerability-management/)及对应版本的维护状态为准；官方流程主要面向 LTS 发行版及其分支。报告时请同时说明 oGRAC 与插件的具体版本、部署架构，以便核实受影响范围。

## 协调披露 / Coordinated Disclosure

请与 SIG Security 协调漏洞披露安排，避免在修复及披露准备完成前公开利用细节。漏洞评估、修复协调、响应时间和公告发布遵循社区官方漏洞管理流程。

已公开的漏洞、受影响版本和修复信息，请查阅 [openGauss 安全公告](https://opengauss.org/zh/security-advisories/)。

## 非安全问题 / Non-Security Issues

一般功能缺陷、兼容性问题和使用咨询，请通过 [oGRAC Issues](https://gitcode.com/opengauss/oGRAC/issues) 反馈。
