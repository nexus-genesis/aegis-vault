# 开发者社区外联包（无壳路线 · agent 可执行 ~85%）

> 定位话术（全部物料统一）：
> 「x402 解决了 settlement，AP2 定义了 mandate 格式，但两者之间的
> **评估引擎 + 可验证证据链**是空缺的。aegis-vault 补这一层：
> 非托管授权护栏，签名快照联签进 AP2 mandate、随 x402 支付走，
> KYA 承诺锚定 ERC-8004。核心 MIT 开源，649 测试，链上 E2E 可复现。」
>
> 生态事实锚点（2026-09 调研，引用时保留出处）：
> - x402 Foundation 2026-07-14 在 Linux Foundation 运作，40 成员
>   （Visa/Mastercard/Stripe/AWS/Google/Cloudflare/Coinbase）
> - x402 交易量 $100M+，90% agentic stablecoin 交易在 Base
> - 生态公认缺口：authorization layer（"you still need an authorization
>   layer (AP2) to prove a human sanctioned the spend" — x402 Foundation
>   builder 指南）

## 使用规则

- 所有帖子从 `nexus-genesis` org 身份发出（开源项目身份，无需法人）
- **不夸大**：只引用仓库里可验证的事实（测试数、npm 包、E2E 脚本），
  不编造用户数/部署数——我们的品牌就是可验证诚实
- 每帖发布前过一遍「会脸红测试」：若有任何句子我们自己都不信，删掉

---

## A. GitHub Discussions 首帖（发布于 aegis-vault 仓库 + 转发引荐）

```markdown
### Show & Tell: aegis-vault — a non-custodial authorization guardrail for x402/AP2 agent payments

We've been building the missing layer between agent payment protocols:
the protocol landscape solved *settlement* (x402) and *mandate formats*
(AP2), but the question every enterprise buyer asks — "how do we cap
what an agent can spend, and who hits the brakes?" — still has no
open-source answer.

**aegis-vault** is that answer:

- `aegis-guardrail-x402` — tiered spend guardrail middleware: small
  payments auto-approve, medium go through a revocable time-lock hold,
  large require human approval, over-limit is denied on-chain. Every
  ALLOW decision emits a **signed authorization snapshot** (self-contained
  evidence, signature excluded from its own preimage).
- `aegis-guardrail-ap2` — co-signs those snapshots into AP2-shaped
  Checkout/Payment Mandate payloads. Verification is fail-closed:
  payload hash + snapshot hash + co-signature must three-way agree.
- `aegis-registry-8004` — KYA (Know-Your-Agent) commitments anchored to
  ERC-8004 identity registries via the spec's setMetadata hook.
- `aegis-vault` core — three-tier key hierarchy (op-key / chain-key /
  snapshot domains via two-level HKDF), envelope v2 encryption with KDF
  floors + AAD binding, human takeover with persistent policy timelock.

Everything is MIT-licensed, 649 tests across 9 workspaces, and the
repo ships a one-command on-chain E2E (deploy → session registration →
agent signing → relayer broadcast → defensive rejection asserts) plus
an offline guardrail E2E you can run in 30 seconds:

    npm run e2e:guardrail --workspace aegis-examples

Honest limitations, stated up front: the AP2 serializer targets v0.2
field names (pluggable per spec version — SD-JWT envelope is left to
integrators); the ERC-8004 Validation Registry address must be supplied
explicitly because the reference deployment hadn't shipped when we
wrote the client; nothing here is custody.

Repo: https://github.com/nexus-genesis/aegis-vault
Packages: `aegis-guardrail-x402`, `aegis-guardrail-ap2`, `aegis-registry-8004` on npm

We're looking for design partners who want the first real deployments —
especially teams shipping x402 endpoints who need the guardrail side.
```

## B. x402 生态自我介绍帖（x402 Foundation builders 渠道 / Discord / 工作组）

```markdown
**Guardrail layer for x402 — signed authorization snapshots that ride
along with every payment**

Hi x402 builders. We build aegis-vault: a non-custodial authorization
guardrail that sits *alongside* x402 settlement, not on top of it.

The gap we fill: x402 proves *how* a payment settles; enterprises need
proof of *whether it should have happened*. Our middleware evaluates
every payment against tiered spend policy (auto / revocable hold /
human approval / deny), and on ALLOW emits a signed snapshot that:
(a) co-signs into AP2 mandate payloads (spec-version-pluggable
serializer), (b) lands in an audit hash-chain whose head anchors to
ERC-8004 identity metadata. Dispute evidence = payment + snapshot +
co-signature, three artifacts that must agree.

For sellers accepting x402 on Base: your agent buyers can now present
*policy-bound* payment payloads. For agent builders: your agent gets a
spend budget with receipts, without custody ever leaving your boundary.

MIT, no token, no lock-in. `npm i aegis-guardrail-x402` and the offline
E2E runs in 30s. Seeking design partners for the first production
deployments — DM here or open a discussion on the repo.
```

## C. ERC-8004 社区贡献意向（EIP 讨论区 / ChaosChain RI 仓库 issue）

```markdown
**Contribution: Aegis KYA commitment anchoring via setMetadata + a
reusable verifier for registration files**

We implemented an ERC-8004 binding for agent payment guardrails and want
to contribute back rather than fork the ecosystem:

1. `kyaCommitment()` — keccak256 commitment over the canonical KYA bundle
   (agentRegistry, agentId, kyaUri, ownerFingerprint, sessionPolicyHash,
   auditChainHead). Only the commitment lands on-chain via the
   `setMetadata` hook under two reserved keys
   (`aegis.kya.commitment`, `aegis.audit.head`); the bundle lives at
   `kyaUri`. Any bundle change invalidates the commitment — that's the
   point.
2. `verifyBinding()` — a fail-closed verifier other implementers can
   reuse to check a registration file actually carries the binding it
   claims (registry/agentId match, aegis service presence, commitment
   recompute against the fetched bundle).
3. Open question for the group: should the EIP reserve/standardize a
   metadata key namespace (e.g. `kya.*`) so verifiers don't have to
   trust per-project key conventions? We're happy to draft a PR against
   the RI or the spec text.

Code: packages/registry-8004 (MIT). Runbook with the anchoring flow:
docs/runbook/ERC8004-ANCHORING.md
```

## D. 渠道与节奏

> **执行日志（2026-09-07）**：
> - A 已发布 → [aegis-vault#1](https://github.com/nexus-genesis/aegis-vault/issues/1)（公告 issue 形态；gh CLI 不可用且 MCP 无 Discussions API， Discussions 开启后迁移并 pin）
> - C 已发布 → [ChaosChain/trustless-agents-erc-ri#21](https://github.com/ChaosChain/trustless-agents-erc-ri/issues/21)（以 `nexus-genesis` org 身份；提出 `kya.*` metadata 命名空间问题）
> - RI 地址核对附带成果：Validation Registry 已部署且已验证（0xC261...CA2C）→ 发现我们默认 ABI 与 RI v1.2 有偏差（requestHash 必填/参数顺序/tag）→ 已修复并对齐（commit 39a1e54）。外联前核对上游，避免公开出丑——本条记为流程教训。
> - B 待发（x402 社区账号需人类注册）；D3 跟进内容见 A issue 评论区计划

| 渠道 | 帖子 | 时机 | 人类动作 |
|---|---|---|---|
| aegis-vault 公告（issue #1，待迁移 Discussions） | A | ✅ 已发 | 无 |
| ChaosChain RI issue（ERC-8004） | C | ✅ 已发（RI#21） | 无 |
| x402 Foundation builder 社区 | B | A 发出后 3 天 | 注册账号需人类邮箱 |
| Farcaster / X 技术线程 | A 的 1/10 摘要版 | 每周 1 条 | agent 可排程，账号需人类注册 |
| ETHResearch / r/ethereum | KYA 承诺模式技术文（从 C 扩写） | C 有回应后 | 同上 |
| Hacker News Show HN | A 英文改写（去营销化，强调「非托管+fail-closed」） | npm CI provenance 配好后（贴子会被查 GitHub） | 提交需人类账号 |

> 凭证依赖（一次性）：GitHub org 的 PAT 配置到 CI（与 NPM_TOKEN 同一批网页操作）——配好后后续发布可全自动。MCP GitHub 通道已验证可用（issues 类）。

## E. 反模式（自检清单）

- 不写 "revolutionary / game-changing"；只写可验证事实和机制
- 不放数据图（没有真实使用数据前，图表=装点）
- 不攻击竞品/巨头（"巨头看不上"是内部战略语言，永不外发）
- 每帖必含「诚实边界」段——这是我们的差异化，不是弱点
