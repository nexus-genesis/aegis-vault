# Design Partner 工具包 · Stage 2

> 目标（战略 v0.2 §07 Stage 2 门槛）：**1 个 design partner 上生产**，
> 即「第一个外部真实限额部署」——全盘证伪点。
> 本工具包 = 野唐（pilot 打法）+ 集成指南 + 条款 + 外联物料。

## 1. 我们卖什么（对外一句话）

> **非托管授权护栏（Rails-as-a-Guardrail）**：根密钥留在你侧，Keeper 以
> appliance 形态部署进你的边界。我们交付 KYA 身份绑定、分层限额与会话
> 收窄、审计哈希链与链上锚点。不做资金托管，不做VASP业务。

## 2. 目标伙伴画像（按痛感排序）

| 画像 | 痛点信号 | 为什么是我们 |
|---|---|---|
| Agent 平台/框架（要接 AP2/Circle） | 已宣布支持 AP2/x402，但 KYA/限额方案是「coming soon」 | 我们是标准之上的护栏层，不动其协议栈 |
| 企业金库/财务自动化 | 试水 agent 付款但被内审卡住：无法回答「agent 最多能花多少、谁能刹停」 | 链上硬上限 + timelock + 人类接管是现成答案 |
| 钱包/发行方（agent 场景） | 合规团队要求 Know-Your-Agent 证据链 | KYA 绑定 + ERC-8004 锚点 + 审计哈希链 |
| x402 生态开发者工具 | 需要支付护栏中间件 | `aegis-guardrail-x402` 即插即用 |

**排除**：纯模型厂商、纯身份协议（是我们的上游/标准层，不是客户）。

## 3. 交付物与集成面（全部可运行、有测试）

| 集成点 | 包 | 集成耗时（实测口径） |
|---|---|---|
| x402 支付护栏（决策引擎 + 签名快照） | `aegis-guardrail-x402` | ~2 小时 |
| AP2 Mandate 联签（可插拔序列化） | `aegis-guardrail-ap2` | ~2 小时 |
| ERC-8004 身份锚定（KYA 承诺上链） | `aegis-erc8004` + runbook | ~3 小时 |
| 会话/密钥托管（三级密钥、接管、时限锁） | `aegis-vault` + `aegis-agent-sdk` | 0.5–1 天 |
| 测试网真实结算 E2E | `scripts/testnet-settle.mjs` | 随包可跑 |

**1 天承诺**：外部开发者 1 个工作日内跑通「注册 agent → 限额策略 →
x402 支付被护栏评估 → 签名快照 + AP2 mandate 联签 → KYA 锚上 ERC-8004」全链路。

## 4. Pilot 条款（起点模板，供法务过）

- **期限**：90 天 pilot，可提前 7 天无责退出
- **形态**：非托管 appliance，部署在客户边界内；我们不持有客户根密钥、
  不触碰资金托管
- **数据权属**：审计哈希链与授权快照归客户；我们仅在客户书面同意下将
  **去标识化**的限额触发/出险统计纳入风险基准数据集（Stage 3 数据飞轮的
  合规前提——此条必须在合同里写清）
- **费用**：pilot 期免费；转正按 受管 agent 数 × 月费（$5–20/agent·月）或
  托管资产 bps，二者取高
- **支持**：异步支持 + 每周一次 30 分钟同步

## 5. 外联节奏（70% 可 agent 执行）

| 步骤 | 执行者 | 产物 |
|---|---|---|
| 1. 候选清单 15–20 家按画像打分 | Agent | `candidates.md`（得分矩阵） |
| 2. 首轮外联（EN 模板 §6） | Agent 起草，**人类署名发出** | 邮件/DM |
| 3. 技术深聊（演示 testnet E2E） | Agent 可全程执行 | 会议 + demo |
| 4. Pilot 协议 | 人类法人 | 签署文件（治理硬依赖） |
| 5. 联盟申请（x402 执行方 / APA 观察员） | Agent 起草 70% | 申请材料 |

> 治理约束（v0.2 §07）：Stage 2 联盟申请约 70% agent 可执行；合同签署
> 必须人类法人——需提前物色人类法人合作方。

## 6. 外联模板

### EN（首轮，发平台方 BD/工程负责人）

```
Subject: Guardrail layer for your agent payments (non-custodial, 1-day pilot)

Hi {name},

{company} is wiring agents into {AP2/x402/Circle payments} — the protocol
side is solved, but the question your enterprise buyers will ask is:
"how do we cap what an agent can spend, and who hits the brakes?"

We built that layer. Aegis Vault is a non-custodial authorization guardrail:
- KYA binding anchored to ERC-8004 (identity you can audit)
- Tiered spend limits with time-locked medium tier + human takeover
- Signed authorization snapshots that co-sign into AP2 mandates and ride
  along x402 payments — usable as dispute and insurance evidence

Root keys never leave your boundary; we deploy the Keeper as an appliance.
Open-source core (MIT), 500+ tests, testnet settlement E2E in the repo.

Worth 20 minutes? We can walk your engineers through a full pilot E2E —
most teams run it in a day. 90-day pilot is free; no custody, no lock-in.

{sender}
```

### CN（备选，中文生态）

```
主题：agent 支付的非托管授权护栏（90 天免费 pilot）

{name} 你好：

{company} 在接入 {AP2/x402/Circle} 支付——协议层已通，但企业客户必然追问：
「agent 最多能花多少？出事谁能一键刹停？证据链给谁看？」

Aegis Vault 是标准之上的授权护栏层（非托管）：
- KYA 身份绑定，锚定 ERC-8004 链上注册表
- 分层限额：小额自动放行 / 中额时限锁（可撤销）/ 大额人工审批
- 签名授权快照：联签进 AP2 Mandate、随 x402 支付走，可作纠纷与保险证据

根密钥不出你的边界，Keeper 以 appliance 部署；核心 MIT 开源，500+ 测试。
1 天可跑通 pilot E2E，90 天免费，随时退出。聊 20 分钟？
```

### 后续跟进模板（第 3/7/14 天，agent 可自动排队）

- D3：附上 `smart-account-e2e` 输出片段 + 仓库链接（证据先于主张）
- D7：附「你们场景下的限额分层建议」半页纸（展示我们读过他们的场景）
- D14：最后跟进 + 明确 CTA（demo 或转介）

## 7. 安全/合规问卷应答要点（RFP 常见题）

| 问题 | 应答锚点 |
|---|---|
| 私钥怎么管？ | 三级密钥域分离（op-key/chain-key/snapshot），根密钥客户自持；加密信封 AES-256-GCM + KDF 地板 + AAD（v2） |
| 策略能被 agent 绕过吗？ | 决策引擎 fail-closed；中额 tier 时限锁持久化（重启不丢）；大额强制人工审批 |
| 出了事证据是什么？ | 审计哈希链 + 链上锚点 + 签名快照/AP2 联签三方吻合校验 |
| 是否构成资金托管？ | 否——非托管 appliance，不持有/不转移客户资金（这是条款级承诺） |
| 合规映射？ | KYA 对齐 FATF KYA 讨论；锚点用 ERC-8004；SOC2 映射在 Stage 3 交付 |

## 8. 本月动作清单

1. [ ] 产出 15–20 家候选得分矩阵（agent 可执行）
2. [ ] 首轮外联 10 封（人类署名）
3. [ ] 演示环境就绪：testnet-settle E2E 一键脚本化（已具备）
4. [ ] x402 执行方申请材料起草（agent 起草 70%）
5. [ ] 1 家进入技术深聊 → 目标：签 1 家 pilot（Stage 2 证伪点）
