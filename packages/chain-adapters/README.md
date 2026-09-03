# aegis-chain-adapters

Aegis Vault cross-chain adapters — **one PQC root identity derives addresses
on every supported chain**. Private keys never leave the agent/browser.

| Chain | Crate | Key type | Address |
|-------|-------|----------|---------|
| Aegis Vault | `aegis-vault` | Dilithium2 (PQC) | `ng1...` |
| Ethereum | `aegis-chain-eth` | secp256k1 | `0x...` (EIP-55) |
| Solana | `aegis-chain-sol` | ed25519 | base58 |

## Install

```bash
npm install aegis-chain-adapters
```

## Usage

```js
import { deriveChainAddresses, deriveAgentFingerprint } from 'aegis-chain-adapters';

// One PQC root identity → addresses on all chains:
const addrs = deriveChainAddresses(pqcPublicKey, pqcPrivateKey);
// { nexus: 'ng1...', eth: '0x...', sol: '6PT...' }

const fingerprint = deriveAgentFingerprint(pqcPublicKey); // stable sha256
```

## API

- `deriveChainAddresses(pqcPublicKey, pqcPrivateKey)` → `{ nexus, eth, sol }`
- `deriveChainAddress(chain, pqcPublicKey, pqcPrivateKey)` → single-chain address
- `deriveAgentFingerprint(pqcPublicKey)` → stable sha256 agent fingerprint

Re-exports the full ETH / SOL adapters (`deriveEthWallet`, `signEth`,
`verifyEth`, `deriveSolWallet`, `signSol`, `verifySol`, …).

## Demo

See [`examples/demo-cross-chain.mjs`](../../examples/demo-cross-chain.mjs) for a
runnable end-to-end demo (PQC root → three-chain addresses → coordination
signature → ETH message signature → human takeover).

## License

MIT