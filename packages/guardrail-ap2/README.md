# aegis-guardrail-ap2

AP2（Agent Payments Protocol）Mandate 联签层。战略定位（v0.2 §07）：
**授权快照 → AP2 Mandate 序列化器（格式仍在迁移，做成可插拔）**。

本包不实现 AP2、不拥有 mandate 格式。它做三件今天就能验证的事：

1. **Bind** — 把已签名的 Aegis 授权快照（来自 `aegis-guardrail-x402` 或任何
   同形快照生产者）的完整性哈希嵌入 AP2 形状的 mandate payload。此后该
   mandate **可证明**受到护栏决策覆盖——或**可证明**没有（校验方 fail-closed）。
2. **Co-sign** — 护栏签名者对（payload 哈希 + 快照哈希）追加联签。
   纠纷证据 = mandate + snapshot + cosignature，三者必须互相吻合。
3. **Adapt** — AP2 字段名集中在单一序列化器模块（当前 `ap2-v0.2`，
   对应 2026-04 FIDO 版 + UCP 2026-01-11 扩展）。规范迁移时注册新
   序列化器即可，绑定不变式永不改。

## 使用

```js
import { createX402Guardrail } from 'aegis-guardrail-x402';
import { createAp2MandateBuilder } from 'aegis-guardrail-ap2';

const guardrail = createX402Guardrail({ agentId, policy, sign });
const { decision, snapshot } = await guardrail.evaluatePayment(payment);

if (decision === 'allow') {
  const builder = createAp2MandateBuilder({ sign, verify });
  const mandate = await builder.toPaymentMandate(snapshot, {
    paymentMandateId: 'pm-1',
    merchantOrigin: 'https://merchant.example'
  });
  // mandate.aegis.snapshot_hash   → 快照哈希
  // mandate.aegis.cosignature     → 护栏联签（覆盖 payload+snapshot）
}

// 校验方（商户/PSP/审计）：
const { ok, errors } = await builder.verifyCosignature(mandate, { snapshot });
```

## 不变量（测试锁定）

- 只有 `decision: 'allow'` 且已签名、未过期的快照能进入 mandate（fail-closed）
- payload 或 snapshot 任一被篡改 → `verifyCosignature` 拒绝
- 无 verify 回调的构建器只能做结构检查，**永远不会**给出 ok:true

## 诚实边界

- **SD-JWT/JWS 信封编码不在本包**：AP2 用 SD-JWT，JOSE 层由集成方负责
  （规范与库选型仍在移动）。本包产出 payload + 签名材料。
- 字段名是暂定的（v0.2 迁移中），映射点唯一集中在 `SERIALIZERS`。
