# SECURITY_INVARIANTS

版本：v1.4（Sprint 2 & 3 & 4 & 5 & 6 & 7 校订）
状态：**Implemented**（10 条不变量详情全部落地；链上强制层已从 JS 语义原型 1:1 移植到 Solidity 合约，签名原像固化跨语言 canonical schema；Sprint 3/4 在链上硬策略之外补齐「链下软策略（Policy Engine）+ Simulation 门禁 + 传输/消息安全」三层；Sprint 5 补齐 P1.3 TLS/mTLS 传输加密 + P1.4 policy 字段(`maxDaily`/`requiresSimulation`) + strict fail-mode + 迁移清理；Sprint 6 补齐分布式状态层（store 抽象 / 共享防重放 / 行级分片 / relayer nonce 协调）；Sprint 7 补齐生产部署运维面（可观测 /metrics + /health + 告警、deployment profile 封装、环境发布 preflight 门禁、secret-store SPI + 生产 mTLS 受控 CA、运维手册）；实现与验证入口见各条"验证入口"与本文件 §4）
上游：`AI agent 链上交易技术白皮书.txt`（Security Baseline v1.0）
适用：aegis-vault / agent-sdk / chain-* / mcp-server 及 Smart Account（Solidity）、Remote Signer、Policy Engine、Simulation Policy、Transport/Message Security 实现

---

## 1. 目的与范围

本文件把白皮书中的安全原则固化为**任何版本都不得违反**的机器可测试不变量。
它不是文档声明，而是 CI、单元测试、合约测试、红队测试共同验收的同一套标准。

每条不变量按生命周期三态标注：

| 状态 | 含义 |
|------|------|
| `Specified` | 不变量已写入本文件，但尚无实现或测试 |
| `Implemented` | 代码已实现该约束（可能仍需独立验证） |
| `Verified` | 有自动化测试/证据证明该约束成立 |

> 写进 SECURITY_ARCHITECTURE.md ≠ 已经实现；代码实现 ≠ 已经验证。

---

## 2. 不变量总表

| ID | 一句话声明 | 生命周期 | 主要强制层 |
|----|-----------|---------|-----------|
| INV-001 | 长期私钥不得进入 Cloud Agent 信任域 | Implemented（MCP 面 + 隔离签名子进程） | agent-keys / agent-sdk / mcp-server |
| INV-002 | 面向 Agent 的签名接口禁止盲签任意 hash | Implemented（SDK 分级 + 隔离 signer 双通道 + 链上 verifier） | agent-keys / agent-sdk |
| INV-003 | 每个 Agent 会话必须有强制过期时间与有界权限 | Implemented（库层 + SDK 资产路径 + 链上策略强制） | agent-keys / agent-sdk |
| INV-004 | 权限只允许缩窄，不得自提权 | Implemented（库层） | agent-keys /（默认路径未） |
| INV-005 | Agent 失陷不得修改自身授权上限 | Implemented（链上强制，P0-5） | chain-eth Smart Account |
| INV-006 | Emergency 能力只能"踩刹车"，不得造成资产流出或提权 | Implemented（链上强制，P0-5） | chain-eth Smart Account |
| INV-007 | 最大可能损失必须可量化且有硬边界 | Implemented（链上硬限额层，P0-5） | chain-eth Smart Account |
| INV-008 | 关键行为必须可审计、可撤销、可恢复 | Implemented | agent-keys / mcp-server / Policy Engine / Relayer |
| INV-009 | Agent↔Agent / Agent↔服务 消息传输必须认证 | Implemented（显式开启，fail-closed） | agent-sdk message-security / transport-security |

---

## 3. 不变量详情

每条含：声明、对应白皮书章节、攻击路径测试矩阵、当前状态与违反点。

### 3.0 — 跨语言 Canonical Schema（Sprint 2，本文件所有链上不变量共享）

Sprint 2 把"Smart Account 链上强制"从 JS 语义原型推进为**真 Solidity 合约**，并把签名原像固化为**跨 JS/Solidity 字节级一致**的协议：

- **载荷 schema（固定字段序，勿重排）**：`canonicalizeAssetIntent(session, intent)`（`packages/agent-sdk/src/keys.js`）输出 `type + sessionId + action/chain/asset + amount + recipient/contract/method + nonce + agentId + sessionIssuedAt + sessionExpiresAt`。`sessionId` 为 32 字节 hex——会话已链上注册时取 `session.sessionId`，否则由会话身份（agentId+issuedAt+expiresAt）确定性派生（同一 session token 恒映射同一 id）。
- **签名原像（digest）**：`hashIntentDigest(canonical)`（`packages/chain-eth/src/canonical.js`）≡ Solidity `SmartAccount.hashIntent`（`contracts/solidity/src/SmartAccount.sol` 的 `_hashIntent`）。两者都按**固定 12 字段序**做 `keccak256(concat(...))`，且每一元素恰为 32 字节（`abi.encodePacked` 无歧义）→ 两端可各自重建同一 digest。`hashIntentDigest` 对缺失 amount/nonce/sessionId **fail-closed 抛错**（命名原因），防止对更弱原像出签。
- **签名格式**：`signIntentDigest` / `verifyIntentDigest`（`packages/chain-eth/src/canonical.js`）为**纯 secp256k1 `(r||s||v)` over digest**（无 EIP-191 前缀）、低 S（EIP-2，拒绝可塑性），与合约 `_recover` 逐位一致；agent 链上身份 = PQC 根密钥确定性派生的 EVM 地址（`deriveEthWalletFromPQC`），链上 `ecrecover` 验签。
- **跨语言 golden vector 对照**：同一固定 fixture（私钥 `0x11…11`、`sessionId=0xab…ab`、amount=100、nonce=1 等）在 JS（`packages/chain-eth/test/canonical.test.js`）与 Solidity（`contracts/solidity/test/SmartAccount.t.sol` 的 `GOLDEN_DIGEST`/`GOLDEN_SIG`）两侧各钉一份——digest 与 65 字节签名两端一致（已测：`test_golden_hashIntent_matches_js_digest` / `test_golden_signature_executes` / `test_golden_sig_recovers_to_golden_addr`）。

### INV-001 — Long-term Key Isolation

> **MUST NOT**：任何面向 Agent 的接口返回可导出的长期私钥明文（Dilithium 主/操作密钥、以及由根身份派生的 secp256k1/ed25519 私钥均视为长期密钥）。
>
> **MUST**：长期密钥仅存在于受控 Signer / HSM / 链上地址背后，Agent 只持有 capability。

- 对应：白皮书 §2.1、§4.1、§6.2、§14。
- 状态：**Implemented（MCP 面 + 隔离签名子进程，P0-3）**。
  - 已满足：agent-sdk `createAgentIdentity` 强制 ≥8 位密码，返回加密 envelope（`packages/agent-sdk/src/keys.js`）；mcp-server `handleRegisterAgent` 已移除 `default-secure-agent-password` 默认密码回退——无会话身份时必须提供真实密码（P0-1，已有回归测试）；mcp-server `generate_keypair` 不再返回 `privateKeyHex`，仅返回地址与派生链地址，临时私钥用 `secureZero` 即时清零（P0-2，`mcp-server/src/server.js`）；P0-3 起 mcp-server 默认写路径与 agent-sdk `signAgentAsset` 默认路径都把解密密钥交给**隔离签名子进程**（`spawnAgentSigner` → `packages/agent-keys/src/signer.js`）持有并出签。交叉验证加固：mcp-server 的 fallback 钱包改为**惰性物化**——仅在 signer 子进程无法 spawn 时才在主进程恢复密钥（且降级显式可见），正常路径主进程不持有可用密钥材料（否则被攻陷的父进程可直接调 `session.wallet.sign()` 同时绕过隔离 signer 与 worker 策略，令隔离形同虚设）；forum 写路径同样经 signer-backed shim 走隔离 signer 出签。
  - 边界说明：chain-eth/chain-sol 的 `deriveWalletFromPQC` 仍会派生 secp256k1/ed25519 私钥——这是链签名适配器的功能性 API（密钥归持有人/未来 Remote Signer 所有），不属于"面向 Agent 的暴露面"；P0-3 已把 agent-sdk / mcp-server 的默认签名路径纳入隔离签名子进程持有。
- 攻击路径测试矩阵：
  - 调用 `generate_keypair` → 响应体不得包含 `privateKeyHex`（已测，`mcp-security.test.js`）。
  - `createAgentIdentity({})` / 短密码 → 必须抛错。
  - mcp `register_agent` 不带 password 且无 session 钱包 → 必须失败（不得回退默认密码）（已测）。
  - 攻击者持默认密码尝试恢复已生成 envelope → 必须失败（AES-GCM 认证失败）。

### INV-002 — No Blind Signing

> **MUST NOT**：面向 Agent 的公开签名接口接受"任意 hash + 外部 amount"组合并直接出签。
>
> **MUST**：签名前完成 `Intent → Decoded Transaction → Simulation → Signer`（白皮书 §7 语义），且 Signer 必须能验证"被签内容与声称金额一致"。

- 对应：白皮书 §7、§9。
- 状态：**Implemented（SDK 分级 + 隔离 signer 双通道 + 链上 verifier）**。
  - 已满足：agent-sdk 引入签名分级通道（P0-2，`packages/agent-sdk/src/keys.js`）——`classifySignRequest` 按 intent 结构判定 tier；通用通道 `signAsAgent` 对资产类 payload（transfer/approve/permit/swap/...）fail closed；高风险通道 `signAgentAsset` 强制要求有效、在作用域内的 session key，并把签名绑定到结构化 intent + 会话上下文。P0-3 起隔离 signer 提供两个出签通道：`signMessage`（policy-less，仅限元数据——mcp-server 默认任务写路径与 forum 写路径使用它）与 `sign`（带 worker spend policy + amount 绑定——`signAgentAsset` 默认路径使用它）。交叉验证加固：`signMessage` 在**worker 侧**（父进程攻陷后仍存活的强制层）与父侧均拒绝 hash 形态消息（`0x`/裸 64-hex，即 `hashAssetIntent` 输出形态）——协议内资产 intent hash 无法经元数据通道绕过 worker 策略出签。
  - P0-4 已闭环资产路径的金额绑定（amount-hash unlinkability）：`signAgentAsset` 默认改签**可解码的 canonical 载荷**（`JSON.stringify(canonical)`，内含 amount）而非单向 hash；隔离 signer 新增 `sign_intent` 通道——worker 从**被签载荷内部**提取金额执行 spend policy，策略检查与被签内容是同一对象，攻陷父进程无法用 `amount:"1"` 换取大额出签（`packages/agent-keys/src/signer-worker.js` / `signer.js`）。agent-sdk 新增链上 verifier（`packages/agent-sdk/src/verifier.js`）：`verifyAgentAssetSignature` 解码被签载荷的 amount 并验签，`enforceAmountBinding` 强制"被签金额 == 交易声称金额"并施加策略上限——独立于 signer 进程的链上强制层（INV-002/003/007 支撑）。
  - Sprint 2（Solidity 化）：链上强制层落地为**真 Solidity 合约**（`contracts/solidity/src/SmartAccount.sol`），`executeFromAgent` 对 12 字段 canonical digest（`hashIntent`，与 JS `hashIntentDigest` 字节一致）做 `ecrecover` 验签——amount 是被签字段之一，单笔上限/白名单/会话绑定均在链上对**同一被签值**复检；签名格式（纯 secp256k1 `(r||s||v)`、低 S、无 EIP-191 前缀）与 JS `signIntentDigest`/`verifyIntentDigest` 逐位一致。跨语言 golden vector 已钉死（§3.0）。
  - 残余限制：legacy `sign` 通道（hash+amount IPC）保留 amount-hash unlinkability（源码已声明为已知架构限制），仅限把金额绑定落在别处的 hash 签名调用方（如链上 Smart Account 独立校验交易金额）；`sign_message` 通道对非 JSON 消息无结构分类——这些路径的最终强制仍须落在链上 verifier / Smart Account（见 INV-007）。
  - P0-4 交叉验证修复（PoC 证实后闭合）：被攻陷父进程可将 `JSON.stringify(资产载荷)` 路由进 policy-less 的 `sign_message` 通道——P0-3 的 hash 形态守卫只挡 64-hex 字符串，而 P0-4 被签内容恰是 JSON，导致 worker 策略被完全绕过且签名可过链上 verifier（`valid=true, amount=1000000`，maxPerTx=5 下依然出签）。修复：`sign_message` 在 worker 侧（权威层）与父侧（fail fast）拒绝 `type=agent_asset_intent` 的 JSON 载荷——即链上 verifier 信任的确切形态；协议自身资产路径已全闭环，残余仅为不携带该 type 标记的外部协议 JSON 形态（其验签契约不在本协议内）。
- 攻击路径测试矩阵：
  - `amount:"1"` + 大额载荷混合提交 → 必须 fail closed（已测：`enforceAmountBinding` 解码被签载荷金额与声称金额不一致即拒绝，INV-002/P0-4）。
  - 直接调用 generic 通道签资产类 payload → 拒绝（已测，agent-sdk.test.js）。
  - 资产载荷经 `signMessage` 元数据通道绕过 worker 策略（父侧 + raw IPC worker 侧）→ 双侧拒绝（已测：P0-4 交叉验证回归）。
  - 任务元数据签名（claim/submit/verify）与资产转移签名 → 走不同通道、不同权限集（已实现分级并测试）。
  - 同一载荷以不同声称金额提交 → 验证结果一致且为拒绝（已测：金额漂移矩阵，INV-002/P0-4）。

### INV-003 — Bounded Session

> **MUST**：每个会话拥有 `expiresAt`，且权限受 `maxPerTx / maxDaily / allowedContracts / allowedMethods / allowedChains` 约束。
>
> **MUST NOT**：存在无到期、无额度、无目标约束即可签名的会话。

- 对应：白皮书 §2.2、§6.3、§10。
- 状态：**Implemented（库层 + SDK 资产路径 + 隔离 signer 派生策略 + 链上策略强制）**。
  - 已有：`createSessionKey` / `checkSessionAccess`（`packages/agent-keys/src/session.js`）；P0-2 新增 `signAgentAsset` 强制会话校验（缺失/伪造/过期/超限/越白名单均 fail closed），并把签名绑定到 intent + 会话上下文（`packages/agent-sdk/src/keys.js`）；会话验签强制要求 `issuerPublicKey`——无发行方验签即拒绝，Agent 不得自我授权会话。P0-3 起 `spawnAgentSigner` 在传入 session 时会从会话硬顶推导 signer 子进程侧 spend policy（`maxPerTx/maxDaily`），使隔离签名子进程独立强制执行同一额度——第二道进程隔离强制层。
  - 缺口：mcp-server 默认执行路径的任务签名（元数据通道）暂不引入会话 key 模型（见 INV-002 分级）；链上策略强制已由 `enforceAmountBinding` 提供（P0-4，`packages/agent-sdk/src/verifier.js`）——含会话过期重放拒绝（P0-4 交叉验证补充：已签载荷在 sessionExpiresAt 过后被链上 verifier 拒绝，无 expiry 字段 fail-closed）。
  - Sprint 2（Solidity 化）：Solidity 合约（`contracts/solidity/src/SmartAccount.sol`）提供完整链上会话层——`registerSession`（owner only，硬限额必填）、`revokeSession`、会话过期/撤销/未注册即时拒绝、whitelist（chain/asset/contract/method/recipient）二次强制、payload 与注册会话的 agentId/issuedAt/expiresAt 一致性校验（`InvalidSession`），并在 `executeFromAgent` 内以 `ecrecover` 复验会话绑定 EVM 地址。
- 攻击路径测试矩阵：
  - 过期会话提交 → `allowed:false`（已测：signAgentAsset 拒签合法签名但已过期的会话）。
  - 会话有效期内签出的载荷在过期后重放 → 链上 `enforceAmountBinding` 拒绝（已测：INV-003/P0-4 交叉验证）。
  - 单笔 501 超 maxPerTx=500 → 拒绝（已测：signAgentAsset 超限 intent）。
  - 分拆 5×101 突破 maxDaily=500 → 累计拒绝。
  - 白名单外合约 / 方法 / 链 → 拒绝（已测：合约/方法/链白名单外 intent 均拒签）。
  - 恶意金额（`'abc'`、空串、负数）→ fail closed，不抛未捕获异常。
  - 时间戳边界（恰在 expiresAt 前后）→ 结果确定性。
  - 无会话 / 伪造会话 / 缺发行方公钥 → 拒绝（已测：缺失 session、篡改 maxPerTx 后验签失败、缺 issuerPublicKey）。
  - 链上策略上限：已签载荷若金额超 maxPerTx/maxDaily，经 `enforceAmountBinding` 拒绝（已测：INV-003/P0-4 链上强制层）。

### INV-004 — Monotonic Privilege Reduction

> **MUST NOT**：会话/凭据可扩大自身白名单、提高额度、延长过期，或变更 agentId。
>
> **MUST**：任何派生会话只能**缩窄**父会话权限；伪造/未验签会话不得通过 scope 检查。

- 对应：白皮书 §6.4"Agent 不允许自行提高自己的授权等级"。
- 状态：**Implemented（库层）**。
  - 已有：`narrowSession` 单调缩窄（`packages/agent-keys/src/session.js`）；`verifySessionSignature` 必须先于 scope 检查执行（源码注释已强调）。
  - 缺口：未接入 agent-sdk / mcp-server 默认路径。
- 攻击路径测试矩阵：
  - 从受限会话派生"无限制/空白名单"子会话 → 拒绝。
  - 子会话 agentId 与父不同 → 拒绝。
  - 子会话 `maxPerTx/maxDaily` 高于父 → 拒绝。
  - 子会话过期晚于父 → clamp 到父过期。
  - 未签名 / 篡改会话对象通过 scope 检查 → `verifySessionSignature` 返回 false 并拒绝。

### INV-005 — No Self-Escalation

> **MUST NOT**：失陷 Agent 可修改自身 spend policy、提高额度、增加 owner、升级账户实现。

- 对应：白皮书 §2.3、§6.4、§10、§17。
- 状态：**Implemented（链上强制，P0-5 + Sprint 2 Solidity 化）**。
  - 部分基础：`takeoverGuard` 可检测控制权变化（`packages/agent-keys/src/takeover.js`）。
  - P0-5 闭环：Smart Account 链上强制（`packages/chain-eth/src/smart-account.js`）——`SELF_ESCALATION_ACTIONS` 集合（increase_limit / add_owner / transfer_ownership / upgrade / grant_role / set_policy / delegatecall / destroy 等 9+ 类动作）**即使签名有效、即使会话白名单允许，也在链上拒绝**；`registerSession` 仅 owner 可调用——Agent 无法自注册会话或授予自身权限。二级防线：白名单 + 会话绑定使自提权动作即使走到链上也被硬拒。
  - Sprint 2（Solidity 化）：`contracts/solidity/src/SmartAccount.sol` 的 `executeFromAgent` 对 action/method 双维度执行 `_isSelfEscalation`（approve/permit/setApprovalForAll/transferFrom/increaseAllowance/addOwner/grantRole/delegatecall/multicall/selfdestruct 等 30+ 动作，含 {action:'transfer', method:'approve'} 变体）——**签名有效且白名单允许也链上拒绝**（已测：`test_self_escalation_action_rejected_INV005` / `test_self_escalation_method_rejected_INV005`）；`registerSession` 仅 `onlyOwner`（已测：`test_owner_only_register_INV005`）。
- 攻击路径测试矩阵：
  - 将 spend config 从 `limited` 改为 `unlimited` → 链上按自提权 action 拒绝（已测：setPolicy/setMaxPerTx/increaseLimit）。
  - 增加 / 变更 owner → 链上拒绝（已测：addOwner/transferOwnership）。
  - 升级 smart account implementation → 链上拒绝（已测：upgrade/destroy）。
  - 绕过白名单直接发起提权调用（delegatecall / grant_role）→ 链上拒绝（已测：delegatecall/grantRole 即使白名单允许也拒）。
  - 非提权动作仍正常通过链上执行（已测：transfer）。
  - `takeoverGuard` 检测到控制权变化 → 阻断并告警（已有）。

### INV-006 — Emergency Key Is a Brake, Not an Accelerator

> **MUST NOT**：Emergency Key 可 `transfer / withdraw / increaseLimit / addOwner / arbitraryUpgrade`。
>
> **MUST**：Emergency Key 仅可 `pause / revokeSession / disableModule / reduceLimit / freeze`，且不得把自己升级为 Owner。

- 对应：白皮书 §6.5。
- 状态：**Implemented（链上强制，P0-5 + Sprint 2 Solidity 化）**。
  - Smart Account（`packages/chain-eth/src/smart-account.js`）实现了 Emergency brake-only 语义：`emergencyKey` 仅可 `pause` / `revokeSession` / `emergencyReduceLimit`（只降不升）/ `freeze`；`resume` / `unfreeze` **仅 owner 可调用**（Emergency 无法撤销自己的刹车）；`executeFromAgent` 是唯一资金移动路径且只接受会话绑定的 Agent 公钥签名——Emergency key 无任何资产移动/提权路径。
  - Sprint 2（Solidity 化）：`contracts/solidity/src/SmartAccount.sol` 同样实现 brake-only——`pause`/`freeze` 仅 `onlyEmergency`，`resume`/`unfreeze` 仅 `onlyOwner`（Emergency 无法解除自己的刹车，INV-006），`emergencyReduceLimit` 只降不升（提升即 `SelfEscalationRejected("raise-limit")`），且 Emergency key 不存在任何资金移动/执行路径。已测：`test_pause_emergency_only_INV006` / `test_resume_owner_only_INV006` / `test_freeze_emergency_only_INV006` / `test_emergency_reduce_only_INV006`。
- 攻击路径测试矩阵：
  - Emergency 触发 transfer / withdraw → 拒绝（无执行路径，已测：emergency 签名不被任何会话接受）。
  - Emergency 增加自身为 owner / 提高额度 → 拒绝（已测：emergencyReduceLimit 提升被拒；无 addOwner 路径）。
  - Emergency revoke session → 立即生效，且被撤销 Agent 无法撤销 revoke（已测：revoked 会话签名链上拒绝）。
  - Emergency 无法执行 arbitrary upgrade（已测：freeze 是 emergency 唯一"冻结"能力，升级/自提权无路径）。
  - Emergency 可 pause/freeze → Agent 执行立即停止（已测）；owner 才能恢复。

### INV-007 — Bounded Blast Radius

> **MUST**：对任何已签发会话，可给出确定的损失上限：`Max Loss ≤ Time Window × Spending Limit × Allowed Capabilities`。
>
> **MUST NOT**：存在可绕过上限的组合路径（approve/permit/multicall/delegatecall/并行竞态）。

- 对应：白皮书 §2.4、§10、§11。
- 状态：**Implemented（链上硬限额层，P0-5 + Sprint 2 Solidity 化）**。
  - 现状：chain 包已从"纯派生+签名适配器"升级为含链上硬策略层（`packages/chain-eth/src/smart-account.js`）。
  - P0-4：agent-sdk 链上 verifier（`verifyAgentAssetSignature` / `enforceAmountBinding`，`packages/agent-sdk/src/verifier.js`）提供金额绑定原语（INV-002/003 链上支撑）。
  - P0-5：Smart Account 落地 on-chain hard limits——`executeFromAgent` 是唯一资金移动路径，强制：验签+金额绑定+会话过期（复用 verifier）、单笔 ≤ maxPerTx、会话级与账户级日累计 ≤ maxDaily（滚动窗口）、nonce 签入被签载荷且严格递增（签名单次有效）、白名单（chain/asset/contract/method/recipient）二次强制、会话绑定一致性（payload 与注册会话 agentId/issuedAt/expiresAt 必须匹配）。`estimateMaxLoss()` 给出可量化的当前暴露边界（每会话 max loss ceiling = min(剩余会话日额度, 剩余账户日额度)，perTx 单笔上限独立报告）。
  - Sprint 2（Solidity 化）：`contracts/solidity/src/SmartAccount.sol` 以**硬编码顺序**执行全部边界：`ecrecover` 验签（低 S，EIP-2）→ nonce 严格递增（`BadNonce`）→ action/method 自提权守卫 → 白名单五维复检 → 单笔 ≤ maxPerTx（`AmountExceedsPerTx`）→ 账户级日累计（`_rollAccountWindow`，独立 24h 滚动窗口）→ 会话级日累计（`_rollWindow`）→ 提交。`estimateMaxLoss()`/`sessionMaxLoss()` 输出可量化暴露。已测（`contracts/solidity/test/SmartAccount.t.sol`）：`test_per_tx_ceiling_INV007` / `test_session_cumulative_ceiling_INV007` / `test_account_cumulative_ceiling_INV007` / `test_nonce_replay_rejected_INV007` / `test_nonce_must_increase_INV007` / `test_register_requires_ceilings_INV007` / `test_estimate_max_loss_INV007`。
  - P0-5 交叉验证修复 1（PoC 证实后闭合）：nonce 原先仅由调用方提交、不在被签载荷内——同一被截获签名可换新 nonce 无限重复执行（仅受日累计约束），"nonce 防重放"实为精确对防重放。修复：`executeFromAgent` 要求 `payload.nonce` 存在且与提交 nonce 一致（缺失 fail-closed），签名变为单次有效。
  - P0-5 交叉验证修复 2（PoC 证实后闭合）：`approve`/`permit`/`setApprovalForAll`/`transferFrom`/`increaseAllowance` 原先不在自提权集合内（文档声称已拒但不实）——`approve(0xAttacker, 100)` 在链上被执行，攻击者获得带外 pull 权限，后续 transferFrom 在 executeFromAgent 之外拉款，单笔/日累计上限全部失效。修复：新增 `ALLOWANCE_SURFACE_ACTIONS` 拒绝集（action 与 method 双检），即使 owner 白名单显式允许也链上拒绝，直至模拟层可量化 allowance 为潜在敞口；owner 显式 opt-in + 模拟属后续工作。
  - Sprint 3（Simulation 门禁，INV-007 支撑）：`mcp-server/src/simulation-policy.js` 把广播前模拟正式化为**风险分级**——`transfer/transferFrom/approve/withdraw/deposit/swap/bridge/raise-limit/add-owner/remove-owner/upgrade/grant-role/revoke-role/pause/freeze` 等资金/特权类动作必须经**成功模拟且处于 60s 窗口内**方可广播（未过 → fail-closed，省 gas、防误投）；只读类（balance/view/getAllowance/status 等）可跳过；**未知 action 一律视为 required**（宁可拦，不可放，`classifySimulationRisk`）。arming 随 `SMART_ACCOUNT_STATE_FILE` 落盘、重启按绝对时间恢复——既不丢保护记录、也不误失效进行中的 preview。
  - Sprint 5（P1.4 policy 字段 + gate 恒开，INV-007 支撑）：①`requiresSimulation`（T2.2，`resolveSimulationRequirement`）策略可**只收紧**静态风险分级（policy 要求模拟而静态标 skippable → 以策略为准；策略标 skippable 而静态 required → 仍 required，保守并集），execute 门禁与 `smart_account_simulation_policy` 查询工具同源单次读取；②`maxDaily`（T2.1）链下软策略按 `accountId+action` 进程内日累计，超限 → `PolicyRejected` fail-closed（省 gas，不浪费链上调用），成功 execute 预留制累计 + 审计 `dailyTotal`（check-then-act 竞态已用"预留在门禁同步段"消除，失败/status-0 回滚）；③**gate 恒开**（T4）——移除 `SMART_ACCOUNT_SIMULATION_GATE=0` 迁移兼容口，preview-first 是唯一执行路径，不可 arm digest 一律 `SimulationRequired`。
  - Sprint 6（多实例分布式，INV-007 支撑）：**多实例共享防重放/状态层下 fail-closed 不放松**。①simulationLog arm + chain state + tx ledger 迁移到共享 store（T1 抽象 + T3 行级分片）：arm 跨实例 LWW 覆盖（安全性由 execute 的 digest 匹配保证，与写入顺序无关）、并发 state 写入 union 合并不丢、不变量冲突（owner/contract 不同）显式 `STATE_CONFIG_CONFLICT` fail-closed 绝不静默取一方；②relayer nonce 协调（T4，`mcp-server/src/relayer-coordinator.js`）：共享 sqlite 上按 `(chainUrl,broadcaster)` 原子分配 EOA nonce（两实例零同 nonce 竞争）+ 广播前跨实例对账去重（同 digest 已落账 → 复用结果不重发，防重复 gas 与台账污染）；链上 `BadNonce`（意图重放）仍 fail-closed 不重试。已知边界：链下 `maxDaily` 软策略仍为进程内日累计（多实例各窗口）——**权威边界仍是链上硬限额**（账户/会话日累计链上强制不变），多实例只影响软策略省 gas 粒度，不放松任何 fail-closed。
  - 缺口：approve/allowance 资金流语义模拟（allowance 量化为潜在敞口 + owner 显式 opt-in）仍为下一阶段（当前 approve 面按自提权拒绝，见 INV-005）；multicall/delegatecall 已按自提权拒绝（INV-005）。
- 攻击路径测试矩阵：
  - `approve(spender, MAX_UINT256)` 表面金额 0 → 链上拒绝（已测：approve/permit/setApprovalForAll/transferFrom/increaseAllowance 属 `ALLOWANCE_SURFACE_ACTIONS`，含 {action:'transfer', method:'approve'} 变体，即使白名单允许也拒；资金流模拟 + owner opt-in 属下一阶段）。
  - multicall / delegatecall 组合绕过单笔限额 → 链上拒绝（已测：delegatecall/multicall 属自提权集合，INV-005）。
  - 并行交易竞态突破日累计 → 账户级独立计数器 + 链上强制（已测：账户级 ceiling 独立于会话级，INV-007）。
  - 跨链桥 / oracle / 合约升级类调用 → 高风险通道或链上拒绝（已测：upgrade/grantRole 等）。
  - 已签载荷金额与声称金额不一致（金额漂移）→ 链上 verifier 拒绝（已测，INV-002/P0-4）。
  - 已签载荷在会话过期后重放 → 链上拒绝（已测，INV-003/P0-4 交叉验证；注册时有效但执行时过期的会话同样拒绝）。
  - 同一签名 nonce 重用 / 乱序 / 换新 nonce 复用签名 → 链上拒绝（已测：nonce 签入载荷 + 严格递增，签名单次有效，INV-007）。
  - 单笔超 maxPerTx / 多笔分拆突破日累计 → 链上拒绝（已测，INV-007）。
  - `estimateMaxLoss` 输出可量化暴露上限（已测：max loss ceiling = min(会话日额度, 账户日额度)）。

### INV-008 — Observable & Revocable & Recoverable

> **MUST**：Intent 创建、Policy 批准/拒绝、签名、广播、Session 创建/撤销、Policy 变更、Emergency 动作均产生审计事件；任何会话可被撤销。

- 对应：白皮书 §15、§16。
- 状态：**Implemented**。
  - 已有：`PolicyTimelock` 的 schedule/revoke/effective/clearAll 通知与 webhook 告警（`packages/agent-keys/src/takeover.js`）；链上 `revokeSession`（仅 owner/Emergency，INV-005/006）。
  - Sprint 3/4（审计/可观测补缺口，`mcp-server/src/audit-log.js` + `observability.js`）：
    - **结构化审计**：setup/preview/execute 全链路 `logStructured` 落 JSON（stderr `[audit]` + `AUDIT_LOG_FILE`），execute 分类成功/失败并带 revert 类别（`AmountExceedsPerTx/BadNonce/InvalidSignature` 等）+ `nonce_conflict/limit_rejected`，事件必达。
    - **Policy 版本审计**：`maybeAuditPolicyChange` 以 sha256 指纹规则集，热更新即记 `policy_change`（旧→新指纹 + 快照 + context），execute 门禁与 `smart_account_policy` 查询均接入；execute 路径**单次读取**策略文件——指纹审计与实际裁决用同一份规则（消除热更新 TOCTOU，杜绝审计轨迹说谎）。
    - **审计 schema 校验**：`AUDIT_SCHEMA` + `validateAuditEntry`，违规 → stderr `[audit] SCHEMA VIOLATION`（不静默、不中断 eval 主路径）。
    - **Relayer 可运营审计**：`executeWithRelayerResilience` 的 attempts / retried / retryable / reconciled 全链路进审计与指标（`smart_account_execute_retried`）；广播后 `wait` 失败先对账 receipt（已落账复用结果，绝不盲目重发，避免白付 gas + 污染 ledger）。
  - Sprint 7（T1/T3：指标/健康/告警可观测）：
    - **Prometheus `/metrics`**（`METRICS_HTTP_PORT` 可选开启，loopback）：`node:http` 输出 Prometheus text；进程采样 gauge + 链上健康（`chain_rpc_up`/`chain_last_block_ts`/`chain_last_block_number`）+ store 形态标签（`store_backend{backend=...}`/`store_shared`）+ 全部计数器（含 relayer 协调维度 relayer_nonce_*/relayer_broadcast_deduped/relayer_lease_failed）。默认关，关闭时与基线逐字节一致；只走独立 HTTP 端口，绝不碰 MCP stdout。
    - **`/health`**（`HEALTH_HTTP_PORT` 可选开启，loopback）：liveness 恒 200；readiness（chain_env / state_store 依赖自检）失败 → 503（LB 摘流），并落 `health_unready` 结构化事件（stdout 不受污染）。`HEALTH_STRICT_STARTUP=1` → 致命依赖失败拒绝启动（`HEALTH_STRICT_STARTUP_FAILED`，与配置 fail-closed 同向）。
    - **告警规则引擎**（`ALERT_RULES_FILE` / `ALERT_RULES_ENABLE_DEFAULTS=1` 可选）：指标阈值 + 窗口 + 严重级，命中写 `alert_fired` 结构化告警事件到 stderr/AUDIT。默认不开启时零成本 no-op。
  - Sprint 5（P1.3/P1.4 审计补缺口）：
    - **mTLS 握手审计**：`createMtlsServer` 成功/失败握手均经 `recordAudit`/`mtls_handshake` 落 JSON（`packages/agent-sdk/src/mtls-server.js`）；失败仅暴露 `tls_*` 类别（不泄露具体校验细节给握手方）。
    - **Policy strict-config 审计**：strict 模式下配置损坏 → execute 拒收带独立 `gate: strict-config`（错误码 `PolicyConfigError`，区别于"缺 preview"的 `SimulationRequired`，不误导运维去补 preview），审计与指标 `smart_account_policy_rejected` 同时落账。
    - **maxDaily/relayer 审计项**：execute 成功审计携带 `dailyTotal`（`store.total` 精确 BigInt 字符串）；relayer attempts/retried/reconciled 延续进审计。
  - 已知限制：审计仍为文件/stderr 输出；Sprint 7 补齐了**可观测面**（/metrics /health /告警，见上），但**防篡改固化（hash-chain）与集中式审计面板仍未闭环**——边界与承接见 SECURITY_GAP_ANALYSIS.md。
- 攻击路径测试矩阵：
  - 会话撤销后继续提交签名 → 拒绝。
  - 告警回调抛异常 → 不破坏 enforcement 主路径（已覆盖）。
  - 关键行为缺审计事件 → 测试断言事件必达。

### INV-009 — Message Transport Authenticity

> **MUST**：显式开启 message security（`createHttpTransport` 的 `messageSecurity`）后，服务端 inbound 请求必须依次通过**信封签名验证 + 身份解析 + 时间新鲜度 + 防重放 + 目标（target==self）校验**；任一不满足 → fail-closed 拒绝。防重放键须在验签**通过后**才记录。
>
> **MUST NOT**：显式开启后存在明文 / 未认证通道；发送侧缺 identity/signer 不得静默降级为未签名请求（构造时即抛错）。

- 对应：白皮书 §6.6（外部 Agent↔Agent / Agent↔服务 通信面）；[SMART_ACCOUNT_TRANSPORT_SECURITY_RFC.md](docs/SMART_ACCOUNT_TRANSPORT_SECURITY_RFC.md) P0。
- 状态：**Implemented（显式开启，fail-closed；MCP 内部信任面不强制，白皮书分层不变）**。
  - 发送侧：`createHttpTransport`（`packages/agent-sdk/src/coordination.js`）加 `messageSecurity` 选项——开启后 POST body 包装为 `{ envelope }`（sender/target/nonce/timestamp/payload/signature，`createMessageEnvelope`）；构造时缺 identity/signer 立即抛错（fail-fast，绝不发送未签名请求）；默认**关**、向后兼容。
  - Canonical preimage 与验签原子性：`verifyMessageEnvelope`（`packages/agent-sdk/src/message-security.js`）按固定字段序拼接 preimage，仅验签通过后才 `replayGuard.record(sender:nonce)`——无效签名的篡改副本不烧 nonce，否则攻击者可抢先投递伪造剧毒化 (sender, nonce)，使随后到达的合法原件被误判重放（DoS）。
  - 运行时化：`createInboundVerifier`（`packages/agent-sdk/src/transport-security.js`）服务端中间层——缺信封 / 身份未知 / 验签失败 / 新鲜度过期 / 重放 / target 不匹配一律 fail-closed；`self` target 校验防**跨服务重放**（signature 只覆盖 target 防篡改、不防"合法签名信封被原样转发给另一个服务"——需接收方显式校验 `target === self`）；`createReplayStore` JSON 文件持久化 + 原子写（tmp+rename），重启不重置防重放窗口（文件损坏仅降级重放检测粒度，不影响验签/身份安全）。
  - Service identity 目录（`packages/agent-sdk/src/service-identity.js`）：did/agentId → 公钥 + verifier，resolve 失败 → `unknown_identity` fail-closed；无 verifier 配置 → `no_verifier_for_identity`。
  - P1.3 传输层 TLS/mTLS（Sprint 5 T1）：`createMtlsServer`/`createMtlsClient`（`packages/agent-sdk/src/mtls-server.js`）强制 TLS 1.3（禁 1.2 及以下）+ 双向证书 + 证书链校验，纯文本 HTTP / 过期 / 伪造证书 / TLS1.2 握手全 fail-closed；证书经 `scripts/gen-mtls-certs.mjs`（纯 node:crypto，无 openssl）本地自签 CA 生成。**与 INV-009 正交**——INV-009 管应用层认证（签名信封/防重放/身份），P1.3 管传输层机密性与双向认证；两者需同时通过（mTLS 握手失败或信封验签失败任一即拒，互不替代）。
  - Sprint 6（T2 共享防重放窗口，多实例）：`createReplayStore` 迁移到 T1 store 抽象——注入共享后端（`createSqliteStore`）后 **claim 恰好一次是全实例族语义**（sqlite `INSERT OR IGNORE` 原子登记）：同一 `(sender,nonce)` 整个服务族只放行一次，跨实例可见、重启不丢；窗口清理按绝对时间 `purgeExpired`（保留期 ≥ 新鲜度窗口，被淘汰的过旧重放仍会被 `timestamp_expired` 拒）+ FIFO 硬上限兜底。**降级矩阵 fail-closed**：local 后端损坏仅显式告警 + 自愈重建（重放检测粒度降级，验签/身份安全不受影响）；**共享模式后端构造/操作错误直接传播（fail-closed）**，绝不静默退化为"各实例独立窗口"——否则同一 (sender,nonce) 可对不同实例各放行一次，多实例安全立即劣化。
- 攻击路径测试矩阵：
  - 明文 POST（缺 `envelope`）→ `missing_envelope` fail-closed（已测：transport-security E2E，mcp-server 全绿）。
  - 未知 sender 身份 → `unknown_identity`。
  - 篡改 envelope（payload / signature）→ `invalid_signature`。
  - 重放同一 (sender, nonce) → `replay_detected`（已测）；伪造源先投递无效签名不烧 nonce。
  - 过期 timestamp → `timestamp_expired`；时间边界确定性。
  - 合法签名信封转发到 `target≠self` 的服务 → `wrong_target` 拒绝（跨服务重放，T1 复核修复已覆盖 + T5.2 E2E）。
  - 开启 messageSecurity 但缺 identity/signer → 构造抛错（不发送未签名请求）。
  - 未开启时行为与现状完全一致（向后兼容，回归 48/48 → Sprint 5 62/62）。
  - mTLS：纯文本 HTTP / 无客户端证书 / 伪造 CA 证书 / 过期证书 / TLS1.2 客户端 / 过期服务端证书 → 握手全拒（已测：`transport-mtls.test.js` 8/8）。
  - mTLS 合法客户端但缺信封（明文 body over TLS）→ 应用层 `missing_envelope` 拒（已测：`transport-mtls-e2e.test.js`——证书合法仍拒，层独立 fail-closed）。
  - signed transport + mTLS + replay guard 三层组合：mTLS 通过 + 信封验签通过 + 防重放通过 → 200；重放同一信封 over mTLS → `replay_detected`；服务端重启后 replay store 持久化仍拒重放；跨服务转发 → `wrong_target`（已测：`transport-mtls-e2e.test.js` 6/6 + replay 持久化恢复）。

---

## 4. 验证方式（CI 集成）

每条不变量对应一组自动化测试；正式包入口 `npm run test:release-packages` 覆盖 6 个正式发布包，验收口径：**所有攻击路径 fail closed**，且必须有可引用的测试/链上收据证据（`Architecture → Threat → Invariant → Control → Test → Evidence`）。

### 4.1 测试入口映射（当前仓库）

| ID | 测试文件 | 关键断言 |
|----|---------|---------|
| INV-001 | `mcp-server/test/mcp-security.test.js`、`packages/agent-sdk/test/agent-sdk.test.js` | generate_keypair 无 privateKeyHex；弱密码/无密码注册拒绝；默认路径走隔离 signer |
| INV-002 | `packages/agent-keys/test/signer.test.js`、`packages/agent-sdk/test/agent-sdk.test.js` | signMessage 拒绝 hash 形态；sign_intent 验签；金额漂移/同内容不同金额拒绝 |
| INV-003 | `packages/agent-sdk/test/agent-sdk.test.js`、`packages/chain-eth/test/smart-account.test.js` | 过期会话载荷拒绝；无 expiry fail-closed；白名单违反拒绝；撤销会话拒绝 |
| INV-004 | `packages/agent-keys/test/session-narrowing.test.js`、`packages/agent-keys/test/session.test.js` | narrowSession 单调缩窄（空白名单/跨 agentId/超上限/晚过期均拒绝）；verifySessionSignature 先于 scope 检查 |
| INV-005 | `packages/chain-eth/test/smart-account.test.js` | 自提权 action（addOwner/upgrade/grantRole 等 9+ 类）即使签名有效也链上拒绝 |
| INV-006 | `packages/chain-eth/test/smart-account.test.js` | Emergency 仅可 pause/revoke/reduce(只降)/freeze；resume/unfreeze 仅 owner；无资产移动路径 |
| INV-007 | `packages/chain-eth/test/smart-account.test.js`、`mcp-server/test/mcp-smart-account-sim-policy.test.js`、`mcp-server/test/mcp-smart-account.test.js` | 单笔≤maxPerTx、日累计、账户级独立上限、nonce 签入载荷且单次有效、allowance 面拒绝、estimateMaxLoss 可量化；`requiresSimulation` 只收紧不放宽；`maxDaily` 预留制累计；gate 恒开（preview-first sole path） |
| INV-007（多实例） | `mcp-server/test/smart-account-distributed.test.js`、`mcp-server/test/relayer-coordinator.test.js` | arm 跨实例 LWW + digest 匹配放行/异 digest 拦截；并发 state union 不丢；不变量冲突 STATE_CONFIG_CONFLICT；双实例并发 20 nonce 全局唯一 + 租约 instanceId 归因；对账去重（recordTx digest 写穿 → isAlreadyLanded 命中）；链上重同步 syncAtLeast 只升不降 |
| INV-008 | `packages/agent-keys/test/*`、`mcp-server/test/mcp-smart-account-t2.test.js`、`mcp-server/test/mcp-smart-account-smoke.test.js`、`mcp-server/test/relayer-operations.test.js` | PolicyTimelock 通知/撤销；audit schema 校验；policy_change 指纹审计；relayer attempts/retried/reconciled 进审计（对账不重发） |
| INV-009 | `packages/agent-sdk/test/message-security.test.js`、`packages/agent-sdk/test/transport-security.test.js`、`packages/agent-sdk/test/transport-mtls.test.js`、`packages/agent-sdk/test/transport-mtls-e2e.test.js` | 验签通过后才 record anti-replay；明文/未知身份/篡改/重放/过期/target≠self fail-closed；replay store 原子持久化；mTLS 明文/伪造/过期/TLS1.2 fail-closed（8/8）；signed transport + mTLS + replay guard 全链路三层组合 + 重启持久化 + 跨服务重放（6/6） |
| INV-009（多实例） | `packages/agent-sdk/test/store-interface.test.js`、`packages/agent-sdk/test/transport-distributed.test.js` | local/sqlite 双后端语义一致 + 原子 readModifyWrite + claim 恰好一次；双实例共享 replay store：首 200 / 次 403 / 重启不丢 / 共享后端降级 fail-closed（不静默退化为各实例独立窗口） |
| INV-008（Sprint 7 可观测） | `mcp-server/test/metrics-sprint7.test.js`、`mcp-server/test/health-alerting.test.js` | `/metrics` 开启→Prometheus text + 进程/链上健康/store 标签维度、未设端口→不监听（基线不回归）；readiness 依赖失败→503、`HEALTH_STRICT_STARTUP=1` fatal 失败→拒绝启动；告警规则命中→`alert_fired` 落审计、关闭 gate→无行为变化 |
| INV-008/Sprint7（profile） | `mcp-server/test/deployment-profile.test.js`、`mcp-server/test/release-preflight.test.js` | production 缺操作键/artifact → fail-closed 抛 `code`；local 缺 RPC 不报错；dry-run 不监听端口；preflight 缺密码/缺 artifact → exit 1，满足 → exit 0；6 包版本 lockstep |
| INV-001（Sprint 7 密钥） | `mcp-server/test/secret-store.test.js` | env: 引用读 process.env / file: 引用读文件（trim）/ 裸值原样；kms 后端无 provider → `SECRET_KMS_NOT_CONFIGURED` fail-closed；provider 可插拔；chain-config 走 resolver（file: 解析为真实密钥），缺省 env 直读不变；生产 mTLS 缺受控 CA → 拒绝（不回退自签）、受控 CA 签发 + 身份绑定 + 不写 ca-key.pem |

### 4.2 发布后 registry smoke（v0.5.0 起）

`scripts/release-smoke.mjs` + GitHub Actions `npm-publish.yml` 的 `registry-smoke` job：从 npm registry 全新安装 **本次 tag 固定版本**（由 publish job 同款 package.json 读出，非 `latest`）的全部 6 包，端到端验证 agent-sdk 身份/签名/verifier、chain-eth Smart Account 执行流（INV-005/006/007 矩阵）、chain-sol 签名往返、chain-adapters 多链地址派生、agent-mcp 可加载。

---

## 5. 修订与豁免

- 任何违反不变量的事务（Issue / PR / 测试失败）必须显式标记对应 INV ID。
- 豁免必须经安全评审书面批准，且豁免单内注明替代控制与截止时间；不允许默认豁免。
- 本文件与实现状态分离维护：实现与差距跟踪放 `SECURITY_GAP_ANALYSIS.md`，不污染本文件的长期规范。
