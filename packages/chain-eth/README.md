# aegis-chain-eth

Aegis Vault Ethereum adapter — deterministically derive an EVM wallet
(secp256k1) from an agent's PQC root identity, with EIP-191 signing and a
spend-mode → guardian-policy mapping so human takeover carries to EVM.

Private keys never leave the agent/browser. The ETH key is a **derived**
secondary key; the agent's true root secret is the Dilithium2 PQC key.

## Install

```bash
npm install aegis-chain-eth
```

## Usage

```js
import { deriveEthWallet, deriveEthWalletFromPQC, signMessage, verifyMessage } from 'aegis-chain-eth';

// From a 32-byte seed (e.g. an agent op-key seed)
const wallet = deriveEthWallet(Buffer.alloc(32, 0x11));
console.log(wallet.address, wallet.privateKeyHex);

// From a PQC private key (quantum-resistant root)
const { deriveEthWalletFromPQC } = await import('aegis-chain-eth');
const eth = deriveEthWalletFromPQC(pqcPrivateKey);

// Sign / verify (EIP-191 recoverable)
const sig = signMessage('hello agent', wallet.privateKeyHex);
verifyMessage(wallet.address, 'hello agent', sig); // true
```

## API

- `deriveEthPrivateKey(seed)` — domain-separated HKDF → 32-byte secp256k1 key
- `deriveEthWallet(seed)` → `{ privateKeyHex, address }`
- `deriveEthWalletFromPQC(pqcPrivateKey)` → ETH wallet from a Dilithium2 key
- `addressFromPrivateKey(privKey)` / `addressFromPublicKey(pubKey)` (EIP-55)
- `signMessage(message, privKey)` / `verifyMessage(address, message, sig)`
- `mapSpendToGuardianPolicy(spendConfig)` — spend mode → EVM guardian policy

## Concept

```
PQC root key (Dilithium2, FIPS 204)
   │  sha256 → 32-byte seed
   ▼
HKDF('nexus/chain/eth/v1') → secp256k1 private key → ETH address
```

The human-takeover spend model (`unlimited` / `limit` / `require-approval`)
maps to an EVM guardian-contract policy via `mapSpendToGuardianPolicy`.

## License

MIT