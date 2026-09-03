# aegis-agent-sdk

**Aegis Vault Agent Coordination Framework** — two pillars:

- **`keys`** — autonomous key security (PQC, self-custody, **human takeover**) via `aegis-vault`. Private keys never leave the agent/browser.
- **`coordination`** — task / proposition / reputation protocol, **chain-agnostic** over a pluggable transport (HTTP or in-memory).

This is the framework that turns the Aegis Vault security standard into a usable agent SDK, decoupled from any specific chain so it can run on Ethereum, Solana, or a local devnet.

## Install

```bash
npm install aegis-agent-sdk
```

Requires `aegis-vault` (pulled automatically). Node >= 18, ESM.

## Keys — create a self-sovereign agent

```js
import { createAgentIdentity, recoverAgentIdentity, signAsAgent } from 'aegis-agent-sdk';

// Generate an identity. The private key is encrypted and NEVER leaves the caller.
const identity = await createAgentIdentity({ password: 'agent-secret-123' });
// { address: 'ng1...', publicKeyHex, envelope, keyModel: 'self-sovereign' }

// Recover when needed (only on the agent's own machine):
const wallet = recoverAgentIdentity(identity.envelope, 'agent-secret-123');

// Sign as the agent:
const sig = await signAsAgent(wallet, { action: 'claim', taskId: 't-1' });
```

## Human takeover — the differentiator

```js
import { takeoverGuard, checkSpendAllowed, SPEND_MODES } from 'aegis-agent-sdk';

// Capture autonomy before an operation...
const before = { type: SPEND_MODES.UNLIMITED };

// ...after the operation, verify the human didn't take over mid-way:
if (takeoverGuard(before, { type: SPEND_MODES.UNLIMITED })) {
  // safe to commit the value transfer
}

// Enforce spend ceilings:
const allow = checkSpendAllowed({ type: 'limit', maxPerTx: 100 }, { amount: 50 });
// { allowed: true }
```

## Coordination — chain-agnostic task loop

```js
import { CoordinationClient, createMemoryTransport, runTaskLoop } from 'aegis-agent-sdk';

// In-memory transport (no network) for local demos/tests:
const transport = createMemoryTransport();
const client = new CoordinationClient(transport);

await client.publishTask({
  agent: 'agent-1',
  title: 'Research quantized models',
  capabilities: ['research'],
  reward: 100,
  taskType: 'research'
});

const tasks = await client.listTasks();
```

For live use, pass an HTTP transport pointed at any Aegis Vault-compatible endpoint:

```js
import { createHttpTransport } from 'aegis-agent-sdk';
const transport = createHttpTransport({ baseURL: 'https://nexus-genesis.top', custodyToken });
```

## Modules

| Import | Purpose |
|--------|---------|
| `aegis-agent-sdk` | all exports |
| `aegis-agent-sdk/keys` | identity + key security |
| `aegis-agent-sdk/coordination` | tasks + governance + transports |

## Tests

```bash
npm test
```

## License

MIT