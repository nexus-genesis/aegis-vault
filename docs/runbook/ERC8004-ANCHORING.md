# Runbook · ERC-8004 锚定（KYA 承诺上链）

> Stage 2 交付：把 aegis-vault 的 KYA 承诺与审计链头锚进 ERC-8004 标准表面。
> 绑定标准，不重定义。规格依据：EIP-8004 Jan 2026（v1.2）。

## 前置

- Node ≥ 18，`aegis-erc8004` 已安装（workspace 内自带）
- 测试网 ETH（Sepolia faucet）与一台 RPC（公共或自有）
- **地址核对（必做）**：`REGISTRY_PRESETS.sepolia` 三地址已于 2026-09-07
  与 ChaosChain RI README「Deployed Contracts」表核对一致
  （github.com/ChaosChain/trustless-agents-erc-ri）。上链前仍建议用
  `https://sepolia.etherscan.io/address/<addr>#code` 复核部署与验证状态。

## 步骤

### 1. 组装 KYA bundle 并计算承诺

```js
import { kyaCommitment, agentRegistryString, buildAgentRegistration, toDataUri }
  from 'aegis-erc8004';

const registry = agentRegistryString(chainId, identityRegistryAddress);
const commitment = kyaCommitment({
  agentRegistry: registry,
  agentId,                    // 注册后回填；首次注册可先出文件再补锚
  kyaUri,                     // HTTPS 上的完整 KYA 报告（人可读 + 机器可校验）
  ownerFingerprint,           // keccak(PQC root public key)
  sessionPolicyHash,          // keccak(canonical session policy)
  auditChainHead              // 审计哈希链当前头
});
```

### 2. 注册 agent（Identity Registry）

```js
import { IdentityRegistryClient, REGISTRY_PRESETS, METADATA_KEYS }
  from 'aegis-erc8004/clients';

const client = new IdentityRegistryClient({
  signerOrProvider: wallet,               // ethers Signer（ funded ）
  addressOrPreset: REGISTRY_PRESETS.sepolia,
  chainId: 11155111
});

const agentId = await client.register(toDataUri(registrationFile), [
  { key: METADATA_KEYS.KYA_COMMITMENT, value: commitment },
  { key: METADATA_KEYS.AUDIT_CHAIN_HEAD, value: auditChainHead }
]);
```

> KYA 承诺在 `agentId` 生成前无法计算完整 bundle——两种顺序：
> a) 先 `register()` 拿 agentId，再 `setCommitment()` 补锚（推荐，测试网用此序）；
> b) 首个锚定先带 sessionPolicyHash/auditChainHead，agentId 用占位并在
>    kyaUri 报告中说明（不推荐，承诺与注册解耦会削弱审计叙事）。

### 3. 补锚（若走顺序 a）

```js
await client.setCommitment(agentId, METADATA_KEYS.KYA_COMMITMENT, commitment);
await client.setCommitment(agentId, METADATA_KEYS.AUDIT_CHAIN_HEAD, auditChainHead);
```

### 4. 请求第三方验证（Validation Registry，可选增强）

Validation Registry 已由 RI 部署到 Sepolia（地址经 README 核对，
2026-09-07：`0xC26171A3c4e1d958cEA196A5e84B7418C58DCA2C`，已含于
`REGISTRY_PRESETS.sepolia`）。注意 RI v1.2 的 `validationRequest`
要求**调用方自行生成 32 字节 `requestHash`**（必填输入，非链上派生）：

```js
import { ValidationRegistryClient, REGISTRY_PRESETS } from 'aegis-erc8004/clients';
import { randomBytes } from 'node:crypto';

const vr = new ValidationRegistryClient({
  signerOrProvider: wallet,
  addressOrPreset: REGISTRY_PRESETS.sepolia   // 用 preset 的 validationRegistry
});
const requestHash = '0x' + randomBytes(32).toString('hex'); // 调用方生成并自存
await vr.requestValidation(validatorAddress, agentId, dataURI, requestHash);
// 之后 vr.status(requestHash) 查询验证结果（response 0-100 + tag）
```

### 5. 验证（校验方视角）

```js
import { verifyBinding } from 'aegis-erc8004';
const res = verifyBinding(registrationFile, {
  agentRegistry: registry, agentId,
  kyaUri, kyaCommitment: commitment, kyaBundle: bundle
});
// res.ok === false 时 res.errors 给出全部不匹配原因（fail-closed）
```

链上复核：`getMetadata(agentId, 'aegis.kya.commitment')` 必须等于
`kyaCommitment(bundle)`；注册文件中 `aegis` service 的 `kyaCommitment`
（若内嵌）必须与链上 metadata 一致。

## 审计叙事（对外一句话）

> 「该 agent 的 KYA 承诺以 32 字节形式锚在 ERC-8004 Identity Registry 的
> 链上 metadata（tx 0x…），任何变更都会使承诺失效；完整 bundle 在 kyaUri
> 可取，Validation Registry 上有独立第三方验证记录。」

## 故障排查

| 症状 | 原因 | 处置 |
|---|---|---|
| `Registered event not found` | preset 地址不是 Identity Registry | 重新核对地址来源 |
| `setCommitment` revert | 非 token owner 调用 | 用注册时同一 owner 签名 |
| 承诺对不上 | bundle 任一字段变化 | 重新 `kyaCommitment()`；不追改，追加新版本并更新审计链 |
| Sepolia gas 波动 | 公共链常态 | 重试即可；本 runbook 不含自动重试（避免掩盖 revert 原因） |
