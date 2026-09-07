# Grant 通道流水线（无壳路线 · 2026-09 调研口径）

> 原则：申请内容 100% 与仓库事实对齐；每个通道标注「核实点」——提交前
> 必须在官方页面二次确认（条款变化快，宁可多查一次）。
> 受益主体：个人/项目身份即可申请（ESP 明确 welcome；KYC 在受助 onboard
> 阶段做，个人可签）——法人壳不是 grant 的前置条件。

## 通道对比

| 通道 | 金额量级 | 匹配度 | 状态（2026-09） | 核实点 |
|---|---|---|---|---|
| **Base Builder Grants** | $5k seed / 1-5 ETH | ★★★（x402/agentic commerce 是明示优先方向；90% agentic stablecoin 交易在 Base） | 开放（paragraph.com/@grants.base.eth） | 当期轮次主题、是否要求「 exclusively on Base」部署 |
| **Optimism Atlas** | 里程碑制，未公布范围 | ★★（public goods + tooling/infra，19 链合格） | 开放（atlas.optimism.io） | 当期轮次开放类别、申请窗口 |
| **EF ESP** | 里程碑制（tooling 类常见 $10-50k 区间，以 GM 沟通为准） | ★★（open-source 开发者工具/公共物品符合 mission；"enabling builders" 语言高度匹配） | 开放（Wishlist/RFP 模式，评审 3-6 周） | Wishlist 当期条目是否有 agent/payments 相关项；2025-08 曾暂停开放申请后重开的申请形态 |

> 排序理由：Base 最快最匹配（小额、方向命中、live product 已有）；
> Atlas 次之（public goods 叙事顺）；ESP 周期最长但品牌背书价值最高，
> 作为并行长线。三者不互斥，可同时申请（各自声明即可，grant 界常规）。

---

## 草案 1 · Base Builder Grants（首发）

**项目一句话**：aegis-vault — the authorization guardrail for x402 agent
payments on Base.

**正文（表单字段化）**

- *What are you building?*
  A non-custodial authorization guardrail for x402/agentic commerce.
  Agents paying via x402 need spend policy + verifiable evidence: our
  middleware evaluates every payment (tiered: auto-approve / revocable
  time-lock / human approval / deny), emits a signed authorization
  snapshot on ALLOW, co-signs it into AP2 mandate payloads, and anchors
  the audit hash-chain head to ERC-8004 identity metadata. Root keys
  stay inside the deployer's boundary; we never touch custody.
- *Live product evidence*（这条是 Base 硬要求）
  - 9 MIT-licensed npm packages published (`aegis-guardrail-x402`,
    `aegis-guardrail-ap2`, `aegis-registry-8004`, `aegis-vault`,
    `aegis-agent-sdk`, chain adapters), registry smoke-tested
  - 649 tests across 9 workspaces, green
  - On-chain E2E in-repo: SmartAccount deploy → agent session
    registration → agent-signed intent → relayer broadcast → typed
    rejection asserts (self-escalation, over-limit), runnable on any
    Base RPC (`CHAIN_RPC_URL=... npm run e2e:smart-account`)
  - x402 guardrail demo E2E (offline, 30s): `npm run e2e:guardrail`
- *Why Base*
  x402's volume is 90% on Base; our guardrail evaluates x402 payment
  payloads and targets Base-native USDC settlement. Demo chain:
  base-sepolia.
- *Milestones (90 days)*
  1. Guardrail adapter for x402 V2 header flow
     (PAYMENT-REQUIRED/PAYMENT-SIGNATURE/PAYMENT-RESPONSE) — publishable
     middleware, testnet-verified settlement guarded end-to-end
  2. First external deployment on Base mainnet (design partner or
     open-source adopter), anchored KYA on ERC-8004 testnet registry
  3. Public dashboard: signed-snapshot explorer sample + audit
     hash-chain verification guide
- *Budget*: $5,000 seed（按当期表单口径；如为 1-5 ETH 模式则取 3 ETH）
  — 开源非商业化交付，无股权诉求
- *Team*: agent-governed open-source project (nexus-genesis org),
  public commit history, verifiable test evidence

**提交前核实**：当期轮次是否接受 open-source 工具类（vs 只收 DeFi app）；
「exclusively on Base」的认定口径（我们 demo 在 base-sepolia，链适配层
支持多链——申请表述聚焦 x402-on-Base 场景，不隐瞒多链能力）。

---

## 草案 2 · Optimism Atlas（并行）

**类别**：Tooling & Infrastructure / Public Goods

**正文**

- *Problem*: Agentic payments are exploding on open rails (x402: $100M+
  volume, 165M+ txns) but authorization — proving a spend was within
  policy and producing court/insurer-grade evidence — is closed-source
  or absent. Without an open guardrail layer, every agent platform
  rolls its own half-solution, and the Superchain becomes the chain
  where uncontrolled agents spend.
- *Solution*: aegis-vault, MIT-licensed: tiered spend guardrail with
  signed authorization snapshots, AP2 mandate co-signing (pluggable
  serializer), ERC-8004 KYA anchoring, human takeover with persistent
  policy timelock. Fail-closed by design: verification rejects any
  payload/snapshot/co-signature mismatch.
- *Public goods case*: the guardrail core (policy engine, snapshot
  format, verification protocol) is open and chain-agnostic; the
  snapshot + audit-chain format we're standardizing is reusable by any
  wallet, facilitator, or insurance protocol — not just our packages.
- *Evidence*: repo stats as in Base draft (649 tests, on-chain E2E,
  npm packages); no users to overclaim — adoption is the milestone.
- *Milestones (2 quarters)*
  1. Open-sourced snapshot verification library for third-party
     facilitators (verify any aegis-signed authorization independently)
  2. Superchain deployment guide + Base/Optimism testnet settlement E2E
  3. External deployment #1 + ERC-8004 anchored KYA, public report
- *Budget*: 里程碑制，按 Atlas 表单口径分三期

**提交前核实**：Atlas 当期轮次（Rollup ecosystem 与 Retro Funding 的
入口区别）；19 链合格清单是否覆盖我们的部署目标。

---

## 草案 3 · EF ESP（长线）

**入口**：esp.ethereum.foundation/applicants → Wishlist/RFP 匹配

**匹配逻辑（申请表里这样写）**

- ESP mission 原文 "strengthening Ethereum's infrastructure... enabling
  builders" —— aegis-vault 是 builder-facing 开源基础设施：让在 Ethereum
  生态上构建 agent 应用（x402/AP2/ERC-8004 全部锚定 Ethereum 系标准）的
  开发者，拿到现成的授权护栏与合规证据链
- 开源承诺：grant-funded work 100% 开源（MIT），与我们的 open-core 一致
  （core MIT，未来商业化只在外围服务——写明这条打消 "non-commercial"
  疑虑）

**Proposal 骨架（按 ESP 模板）**

1. *Problem*: agent payments 标准正在 Ethereum 生态定型（x402 on Base、
   AP2、ERC-8004），但授权评估与证据链层缺失且正在碎片化
2. *Deliverables*
   - snapshot verification protocol v1 文档 + 参考实现（独立可复用）
   - ERC-8004 KYA anchoring spec contribution（含向上游 RI/spec 提 PR）
   - 多链（Base/Arbitrum/主网）测试网结算 E2E 矩阵 + 公开报告
3. *Timeline*: 6 个月，三里程碑
4. *Budget*: $30k 区间（解释：核心开发者 0.5 FTE × 6 月的非 dilutive
   补贴口径，低于市场价——ESP 偏好）
5. *Experience*: 公开仓库、commit 历史、测试证据（不虚构团队履历——
   agent-governed 项目如实陈述治理形态，这本身是诚实差异化）

**提交前核实**：Wishlist 当前条目列表（找 "developer tools"/"security"
相关项挂钩）；2025-08 暂停开放申请后的新申请形态细节。

---

## 执行看板

| # | 动作 | 执行者 | 依赖 | 状态 |
|---|---|---|---|---|
| 1 | Base 表单实际字段核对 + 提交 | agent 起草 → 人类提交（表单可能需邮箱/钱包签名） | 无 | 待办 |
| 2 | Atlas 申请提交 | 同上 | 无 | 待办 |
| 3 | ESP Wishlist 匹配 + proposal PDF | agent 全程 | ESP 模板 | 待办 |
| 4 | Discussions 首帖 + RI issue | agent（org 凭证） | GitHub PAT | 待办（与 NPM_TOKEN 同批配置） |
| 5 | x402 社区帖 | agent 起草 → 人类账号发 | 账号注册 | 待办 |
| 6 | 三个通道结果回填本表 | agent | — | 持续 |
