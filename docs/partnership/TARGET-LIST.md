# Design Partner 目标清单 · 20 家具名（v1，2026-09-08）

> 用途：战略小结 v1 的 Day-7 验收项。每家含痛感假设、切入点、联系路径。
> 规则：触达一次记一行状态；每周更新漏斗。**触达邮件需署名人类身份——
> 未落定前先建清单、练素材、走 GitHub 公开互动（issue/discussion）热身。**
> 来源：awesome-x402 生产部署名录（2026-09-07 版）、Rain APA 26 家创始
> 成员名单（2026-08-18 官宣）、x402 Foundation 成员、仓库生态调研。

## Pipeline 漏斗（每周更新）

| 阶段 | 定义 | 当前计数 |
|---|---|---|
| T 触达 | 发出邮件/issue/DM | 0 |
| R 回复 | 对方回复（含拒） | 0 |
| C 通话 | 真人通话/视频 ≥20min | 0 |
| E 评估 | 对方进入技术评估（跑通 demo） | 0 |
| L 意向 | 签试点意向/LOI | 0 |

---

## P0 · x402 端点团队（自部署 · 首批触达）

痛感共性：自己的 API 正在被 agent 付费调用，消费限额与授权证据靠手搓；
「向企业客户解释谁授权了这笔支出」目前无现成答案。

| # | 团队 | 是什么 | 痛感假设 | 切入点 | 路径 |
|---|---|---|---|---|---|
| 1 | **Arch Tools** (Deesmo) | 58 个生产 API 工具，自建 "patent-pending agent auth" | 自建授权层维护重，且非标准→难被生态认可 | 你的 auth 层可以变成标准化护栏（分层限额+签名快照），省掉自维护 | GitHub: Deesmo/Arch-AI-Tools issue/discussion |
| 2 | **Octodamus** | 33 个 pay-per-call 情报端点，Ed25519 签名响应 | 已在意数据完整性，但对「授权侧」无证据——企业客户问起无话可答 | 快照 = 给你的 API 调用带上「谁授权 agent 花这 $0.01」的可验证回执 | octodamus.com / llms.txt 联系位；GitHub |
| 3 | **LogicNodes** | 619 个 A2A 微服务市场，自证 SHA-256 trust hashes | 多 agent 对多 agent 互付，限额失控面最大 | 每笔互付的护栏快照直接替换自证 hash，升级为可追责证据链 | logicnodes.io agent-guide / GitHub |
| 4 | **JarvisClaw** | LLM 网关 200+ provider，per-user HD 钱包 | 密钥管理最重的一个；家长式限额只有三层缓存没有策略 | HD 钱包上叠会话级策略+人工接管，密钥仍不出你的边界 | docs.jarvisclaw.ai / GitHub |
| 5 | **Stratalize** | 100+ attested 金融/医疗/房产工具 | 合规敏感客群，attestation 已做但授权证据缺失——卖企业客户时最需要的正是后者 | KYA 锚定 + 授权快照补齐你的合规叙事（受监管客户问的第一问题） | stratalize.com / MCP registry |
| 6 | **AfaAgent** | 43 个 x402 API + MCP server | 端点多、单价高（至 $0.99），单笔限额缺失风险敞口最大 | 高价值调用最需要「超阈值转人工」分层 | GitHub: AfaAgent/x402-api-suite |
| 7 | **AI Rook** | 22 端点，EscrowV2 链上结算 | 已有链上结算保护，但授权在链下无人管 | EscrowV2 是结算层证据，快照是授权层证据——互补不冲突 | agents.ai-rook.com / GitHub |
| 8 | **Superhighway** | 生产中搜索 API，$0.001/call | 高频微付，日累计限额是最痛的（微付失控=慢性失血） | 微付自动 + 日累计闸门 + 超限 HOLD，一行中间件接入 | superhighway.walls.sh / npm |
| 9 | **Langston Search** | Solana 主网生产搜索 API | 唯一明确的 Solana 侧生产者——验证「软护栏（快照+审计）」叙事的试金石 | Solana 没有链上强制，快照+审计链恰好是唯一可交付的护栏形态 | langston.click / GitHub |
| 10 | **Kaisha** (hp-vladic) | 日本法人登记官方数据 API | 合规数据源，企业客户尽调型采购——对证据链需求刚性 | 向企业卖数据时附带 KYA 证据 = 提客单的差异化 | GitHub: vladic-corp/kaisha-api |

## P1 · 聚合器 / 市场（既是客户又是分销渠道）

| # | 团队 | 是什么 | 痛感假设 / 价值 | 路径 |
|---|---|---|---|---|
| 11 | **PayAPI Market** (chetparker) | x402 API 市场，10 APIs 65 端点 | 市场方若内建护栏认证（"aegis-guarded" 标签）= 全体卖家的增量信任 | GitHub: chetparker/x402-marketplace |
| 12 | **Bounty API** (vncent786) | agent-native API 市场 | 同上，体量小决策快，适合第一个集成案例 | GitHub: bounty-api |
| 13 | **CDP x402 Bazaar** (Coinbase) | 10k+ 端点的 agent 发现入口 | 渠道位：目录收录 + 未来「guarded endpoint」标准位 | docs.cdp.coinbase.com 渠道 / x402 Foundation 转介 |
| 14 | **x402 Foundation 生态目录** | LF 中立治理下的生态列表 | 收录 aegis-guardrail-x402（今天已上 npm）即零成本分发 | x402.org 提交入口 / awesome-x402 PR（立即可做） |

## P1.5 · 平台 / 框架层（B2B2B，集成 + 按席位）

| # | 团队 | 是什么 | 痛感假设 / 价值 | 路径 |
|---|---|---|---|---|
| 15 | **x402agentic.ai** | middleware+钱包 SDK+spend dashboard（Q2'26 预览） | 他们的 dashboard 没有可验证证据层——快照/审计链可直接嵌；互补非竞争 | hello@x402agentic.ai（公开邮箱） |
| 16 | **ag402** (AetherCore) | Python agent 支付层，648 测试，非托管叙事相同 | Python 侧无护栏对等物——我们是其 JS 对应层 + 可输出快照格式供其实现 | GitHub: AetherCore-Dev/ag402 |
| 17 | **hive-rosetta** (srotzin) | 零依赖 EIP-3009 签名原语（Node+PyPI 同名） | 原语层互补；社区活跃贡献者是我们进 awesome-x402 生态的天然推荐人 | GitHub: srotzin/hive-rosetta |
| 18 | **thirdweb Nebula** | agent 交易框架（大厂） | 观察项：框架级集成谈判周期长，等前 3 家案例落地后再谈 | 官方 discord/support |

## P2 · APA 成员里的中立互操作候选（长线，本周不触达）

> APA 官方触达口：apa@rain.xyz（以「中立 OSS 参考实现」身份申请参与，
> 正是联盟章程要的互操作证据）。以下按互补性排序。

| # | 公司 | 为什么是目标 | 时机 |
|---|---|---|---|
| 19 | **Sardine** | agent 风控；授权快照是其风控引擎的完美输入特征 | 有 1 个端点案例后 |
| 20 | **Basis Theory** | 密钥 tokenization 基建；非托管叙事同源，代理分发 | 有 1 个端点案例后 |
| 21 | **Crossmint** | agent 钱包基建（go+python SDK），需要授权护栏位 | 有 1 个端点案例后 |
| 22 | **Turnkey** | 签名基建 = 我们定价锚点，也是潜在 OEM/合作方 | 谨慎：先对手后伙伴 |
| 23 | **Rain** | APA 召集方；Agent Control Layer 与我们同层不同轨（卡 vs 稳定币 API） | via apa@rain.xyz |

---

## 触达执行规则

1. **首批 5 家**（#1–5）：署名身份落定后 48h 内发出；邮件 = DESIGN-PARTNER-KIT
   模板 + 每家专属切入段（上表），不群发。
2. **GitHub 通道可先行**（无需等署名）：#1/2/6/7/9/10/11/12/16/17 都有公开
   repo——以 issue/discussion 形式做技术互动（非推销），为邮件触达铺认知。
3. **本周即做**：awesome-x402 提 PR 收录 aegis-guardrail-x402（#14 的变体，
   纯 agent 可完成）。
4. **计数纪律**：Day-30 检查点 ≥8 次通话；Day-60 15+ 对话 & ≥1 评估否则触发
   kill criteria 转向（战略小结 v1 §1.3）。

## 信息来源

- awesome-x402 生产部署名录：github.com/xpaysh/awesome-x402（2026-09-07 更新）
- APA 创始成员 26 家：rain.xyz/resources/rain-launches-the-agentic-payments-alliance（2026-08-18）
- x402 Foundation @ Linux Foundation 40 成员（2026-07-14 启动）
