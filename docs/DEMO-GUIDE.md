# Aegis Vault 演示指南

## 已验证的离线演示

从仓库根目录运行：

```bash
npm run e2e:guardrail --workspace aegis-examples
```

需要先安装 monorepo 依赖：

```bash
npm ci
```

本次在当前 Aegis Vault checkout 实际运行成功，终端输出 `E2E PASS`。演示不需要外部 RPC、钱包余额或真实资金。

## 演示流程

1. **x402 护栏决策**：小额请求自动放行并生成签名快照；中额请求进入可撤销 HOLD；大额请求要求人工审批；超过单笔上限的请求被拒绝。
2. **AP2 形状的 Payment Mandate**：把授权快照哈希绑定到 mandate、附加护栏联签，验证 payload、snapshot 和签名彼此吻合；篡改金额后校验失败。
3. **ERC-8004 身份材料**：生成 KYA 承诺并检查 ERC-8004 注册文件是否携带可验证的 Aegis 绑定。

对应实现：`examples/guardrail-e2e.mjs`。真实链上 ERC-8004 写入步骤另见 `docs/runbook/ERC8004-ANCHORING.md`。

## 可对外使用的介绍

> Aegis Vault 是面向 AI Agent 支付场景的非托管授权护栏原型。它在支付回调执行前，根据 Agent 的额度和策略评估支付意图，并为允许的决策生成签名证据；这些证据可以与 AP2 形状的 mandate 和 ERC-8004 身份材料关联。当前离线演示验证了策略分级、篡改检测和身份材料绑定，不执行真实 x402 结算。

## 必须说明的边界

- 演示签名使用 HMAC 占位实现，用来展示签名者无关接口；它不是生产密钥或 PQC 签名。
- 本演示调用 Aegis 的护栏接口，不是完整的 x402 客户端/服务端协议集成，也不会结算 USDC。
- AP2 包负责快照绑定、联签和验证；它不实现完整 AP2 协议，当前字段序列化仍可插拔且处于迁移阶段。
- ERC-8004 演示在本地生成并验证注册文件/KYA 绑定；链上写入是单独步骤。
- 项目上层组合仍处于第三方审计阶段；该演示不能作为生产安全认证。

## 演示时的讲解顺序

1. 先展示策略阈值和四种请求结果。
2. 展示允许决策产生的授权快照，并说明它是可审计证据。
3. 展示 AP2 形状的 mandate 如何绑定该证据，再改动金额让校验失败。
4. 展示 KYA 承诺与 ERC-8004 注册材料的绑定。
5. 明确说明本演示完全离线，签名是 HMAC 占位实现，不发生真实支付或链上写入。

## 定位短句

**英文：** Aegis Vault is a non-custodial authorization guardrail for AI-agent payments. It evaluates payment intents, produces verifiable policy evidence, and connects that evidence to existing identity and mandate ecosystems.

**中文：** Aegis Vault 为 AI Agent 支付提供非托管授权护栏：评估支付意图、生成可验证的策略证据，并将证据关联到现有身份与支付授权生态。

发布或申请资助时，应同时说明：当前展示的是离线原型；完整 x402 结算、完整 AP2 实现和独立第三方审计尚未由此演示证明。