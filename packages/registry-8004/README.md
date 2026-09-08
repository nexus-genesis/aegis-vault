# aegis-erc8004

ERC-8004（Trustless Agents）绑定层。**绑定标准，不重定义**：身份归
ERC-8004 的 Identity Registry，验证归 Validation Registry；本包只做
Aegis KYA（Know-Your-Agent）承诺向标准表面的锚定。

## 能力

| 模块 | 说明 |
|---|---|
| `buildAgentRegistration()` | 产出符合 `eip-8004#registration-v1` 的注册文件（agent card）。Aegis 绑定以自定义 service 条目（`name: "aegis"`）表达——规范明确允许任意 service 名称/端点 |
| `kyaCommitment()` | 对 KYA bundle（registry 身份、owner 指纹、会话策略哈希、审计链头）做 keccak256 承诺。**只有承诺上链**，数据本身留在 kyaUri |
| `verifyBinding()` | 验证方（钱包/审计/保险）用：校验注册文件确实携带 Aegis 绑定且承诺与 bundle 一致，fail-closed |
| `IdentityRegistryClient` | 薄 ethers 客户端：register / setAgentURI / setCommitment（规范 setMetadata 钩子）/ setAgentWallet（EIP-712） |
| `ValidationRegistryClient` | validationRequest / getValidationStatus——KYA 承诺的第三方验证钩子 |

## 快速使用

```js
import { buildAgentRegistration, kyaCommitment, agentRegistryString, toDataUri }
  from 'aegis-erc8004';
import { IdentityRegistryClient, REGISTRY_PRESETS, METADATA_KEYS }
  from 'aegis-erc8004/clients';

const registry = agentRegistryString(11155111, REGISTRY_PRESETS.sepolia.identityRegistry);

const commitment = kyaCommitment({
  agentRegistry: registry,
  agentId: 22,
  kyaUri: 'https://kya.acme.example/22',
  ownerFingerprint: '<keccak(PQC root pubkey)>',
  sessionPolicyHash: '<keccak(active session policy)>',
  auditChainHead: '<audit hash-chain head>'
});

const file = buildAgentRegistration({
  name: 'acme-purchasing-agent',
  description: 'Procurement agent under tiered spend guardrails',
  services: [{ name: 'web', endpoint: 'https://agent.acme.example/' }],
  registrations: [{ agentId: 22, agentRegistry: registry }],
  kyaUri: 'https://kya.acme.example/22',
  kyaCommitment: commitment
});

// 全链上元数据：data URI 或 IPFS
const agentURI = toDataUri(file);
```

链上写入见 [docs/runbook/ERC8004-ANCHORING.md](../../docs/runbook/ERC8004-ANCHORING.md)。

## 诚实边界

- **ABI / typed-data**：函数签名已对齐 ChaosChain RI v1.2 README（2026-09-07
  核对，含 `validationRequest` 的必填 `requestHash`）；事件形状 RI 未列明，
  客户端避免依赖事件取值。全部 ABI 可通过构造参数 `abi` 覆盖。
- **地址**：`REGISTRY_PRESETS.sepolia` 三地址（Identity/Reputation/
  Validation）与 RI README「Deployed Contracts」表核对一致（含核对日期），
  生产使用前仍需复核当期地址；地址必须能链接到出处。
