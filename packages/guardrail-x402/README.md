# aegis-guardrail-x402

x402 payment guardrail middleware (Stage 1 prototype). Answers one question
before an agent payment moves money:

> "May this agent move THIS amount to THIS recipient, right now?"

Decision core is delegated to [`aegis-vault`](https://www.npmjs.com/package/aegis-vault)
tiered spend controls (fail-closed):

| Tier | Verdict | Guardrail output |
|---|---|---|
| small-auto | allowed | signed authorization snapshot (evidence for audit/AP2/insurance) |
| medium-timelock | permitted, delayed | `HOLD` + revocable window metadata |
| large-require-approval | blocked | `approval-required` |
| over-limit / malformed | blocked | `deny` + reason |

Signer-agnostic: pass any `async (preimage) => signature` — session key, PQC
operation key, remote signer or KMS. The signed snapshot is canonical JSON
(deterministic key order, fresh nonce, 5-minute TTL).

## Usage

```js
import { createX402Guardrail, withGuardrail } from 'aegis-guardrail-x402';

const guardrail = createX402Guardrail({
  agentId: 'agent-1',
  policy: { type: 'limit', maxPerTx: '10', maxDaily: '50' },
  spentToday: () => ledger.spentToday('agent-1'),
  sign: (preimage) => sessionKey.sign(preimage)
});

const pay = withGuardrail(guardrail, (payment) => x402Client.pay(payment));
const { allowed, evaluation } = await pay({
  amount: '5', payTo: '0xAbC…', asset: 'USDC', chain: 'base', purpose: 'api-credits'
});
```

## Status

Stage 1 prototype (see `docs/strategy/PRODUCT-POSITIONING-v0.2.md`).
Version `0.1.0` is published to npm. This checkout is version `0.2.0`;
check the npm registry and release tag before describing `0.2.0` as published.
The decision core ships with `aegis-vault`.
