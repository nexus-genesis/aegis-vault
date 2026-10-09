# Design Partner 工具包（早期验证版）

> 本文用于邀请技术团队评估 Aegis Vault 原型，不构成商业报价、生产就绪声明或支持承诺。仓库当前可复现的演示是离线 E2E；联系外部团队前，先让对方看演示指南和限制说明。

## 1. 一句话介绍

Aegis Vault 是面向 AI Agent 支付意图的开源授权护栏原型：按策略评估金额与支付信息，并生成可验证的授权证据。项目探索与 x402、AP2 和 ERC-8004 的衔接方式。

## 2. 当前可验证范围

- x402-shaped 支付意图的离线策略评估：允许、暂缓/需审批或拒绝。
- 离线示例生成授权快照，并演示篡改检测。
- AP2-shaped mandate 的快照绑定及联签验证示例；这不是完整 AP2 协议实现。
- ERC-8004 身份承诺的本地注册文件绑定检查；离线演示本身不执行链上写入。
- 演示签名器是 HMAC 占位实现，不代表生产密钥管理或 PQC 安全能力。

演示命令、结果及明确限制见 [`docs/DEMO-GUIDE.md`](../DEMO-GUIDE.md)。当前演示不执行真实 x402 结算，不应被描述为已验证的生产集成或第三方安全审计。

## 3. 适合的早期评估伙伴

- 正在研究 Agent 支付授权、限额或审计证据的开发者团队。
- 愿意先阅读代码并提供技术反馈、但不要求生产 SLA 的开源项目。
- 能指出真实工作流与当前原型差距的基础设施团队。

目前的目标是验证问题和集成边界，不承诺已有客户、正式合作关系或生产部署。

## 4. 试用方式与边界

建议先从仓库示例自助运行开始。若对方愿意继续，可通过公开 issue/discussion 交流一个具体用例；任何额外开发、部署、响应时限或持续支持，均需另行确认范围、资源和费用后再承诺。

- 不收取试用费，也不承诺免费定制或免费支持期限。
- 不提供托管资金、客户私钥托管或生产密钥管理服务。
- 不收集客户数据；如将来需要任何数据或案例用于公开材料，须先取得明确书面同意。
- 尚无正式商业合同、SLA、合规认证或第三方审计声明。

## 5. 可能的后续商业模式（尚未报价）

只有在完成真实集成验证、确认维护和支持成本后，才讨论付费实施、企业支持或团队功能。若未来对软件服务定价，应基于实际软件用量、团队规模或支持范围；不按客户托管资产比例收费，以保持非托管定位一致。

## 6. 对外首封联系模板（需人工核实后发送）

```text
Subject: Would you evaluate an open-source agent payment guardrail prototype?

Hi {name},

I’m building Aegis Vault, an open-source prototype for evaluating agent
payment intents against spend policies and producing verifiable evidence.

The repository currently includes an offline demo for tiered decisions,
snapshot binding, and tamper detection. It does not yet demonstrate real
x402 settlement, a full AP2 implementation, or production readiness. The
scope and run instructions are here: {repository_link}.

Would this problem be relevant to your team? If so, I’d value feedback on
one concrete workflow or on the prototype’s integration boundary. There is
no commitment to a pilot or production support.

Best,
{sender}
```

发送前请人工确认对方姓名、与对方产品相关的具体理由，以及仓库/演示链接仍然可用。不要群发，也不要暗示对方已经采用或背书 Aegis Vault。
