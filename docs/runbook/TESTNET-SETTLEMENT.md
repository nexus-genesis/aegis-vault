# Runbook — 测试网真实结算（Stage 1 · 真实结算 execute）

目标：把「agent 授权 → 链上硬限制 → 真实广播」的 SmartAccount 链路从本地
anvil/进程内 EVM 搬到公共测试网，完成 Stage 1 的第 4 项技术地基。
预检 + 全流程由 `scripts/testnet-settle.mjs` 一键执行。

## 0. 前置

| 项 | 要求 |
|---|---|
| 合约 artifact | `cd contracts/solidity && forge build --use 0.8.24`（或设 `SMART_ACCOUNT_ARTIFACT`） |
| 测试网 RPC | Sepolia / Base Sepolia 的 JSON-RPC 端点（Infura/Alchemy/公共网关均可） |
| 三个 funded 账户 | owner / emergency / relayer 各 ≥ 0.005 测试网 ETH |
| Node | ≥ 18 |

> 脚本会显式拒绝 anvil 默认私钥与 chainId 31337——真金白银的测试网
> 结算必须用你自己的账户。

## 1. 准备账户与资金

1. 生成三把私钥（任何钱包 / `ethers.Wallet.createRandom()`）。
2. 过水龙头为三个地址充值（Sepolia：Google/Alchemy/pow 水龙头；Base Sepolia：Coinbase 水龙头）。
3. agent key 可以是任意 32 字节（`AGENT_PK`），不需要资金——agent 只离线出签，
   广播由 relayer 完成（这就是「agent 无 gas 权」的护栏设计）。

## 2. 运行

```bash
CHAIN_RPC_URL=https://sepolia.infura.io/v3/<key> \
OWNER_PK=0x… \
EMERGENCY_PK=0x… \
RELAYER_PK=0x… \
AGENT_PK=0x… \
node scripts/testnet-settle.mjs
```

脚本依次执行并断言：

1. **Preflight**：RPC 连通、chainId ≠ 31337、三账户余额达标、artifact 存在
2. **deploy** SmartAccount（owner + emergencyKey + accountMaxDaily），打印合约地址
3. **registerSession**（链上限额 maxPerTx=25 / maxDaily=100，含白名单）
4. **agent 离线出签**（canonical digest + secp256k1）+ 本地验证
5. **relayer 广播** `executeFromAgent`，输出 txHash 与区块号

## 3. 结果判定

- 全部 `[OK]` + `RESULT: 真实测试网结算链路全部通过` → Stage 1 第 4 项完成，
  把合约地址与 txHash 记入审计附件（`docs/audit/`）。
- 任何 `[FAIL]` 都带 `↳` 提示行：gas 不足 / RPC 限速 / 链上 INV-005/006/007
  类型化 revert 的排查入口。

## 4. 与本地模式的差异清单

| 维度 | 本地（examples/smart-account-e2e） | 测试网（本脚本） |
|---|---|---|
| 链后端 | 进程内 LocalChain / anvil | 公共测试网 RPC |
| 账户 | anvil 预充值默认钥 | 自备 funded 账户（强制） |
| 时钟 | 本地 | 链上最新块时间（防漂移，INV-003） |
| 成本 | 零 | 真实测试网 gas |
| 断言 | 链上状态 + revert 类型 | 同 + 部署/广播真实上链 |

## 5. 下一步（Stage 2 预告）

- 把 `remote-signer` Keeper（staging 已验证 5/5）接到本脚本第 4 步：
  agent 私钥不出进程 → 远端签名服务出签 → 测试网广播。
- ERC-8004 Identity Registry 锚定：注册 KYA 承诺哈希（`deriveAgentFingerprint`）。
