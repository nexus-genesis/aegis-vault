# aegis-chain-sol

Aegis Vault Solana adapter — deterministically derive a **Solana keypair
(ed25519)** from an agent's PQC root identity, with base58 addresses and
message signing. Private keys never leave the agent/browser.

The Solana key is a **derived** secondary key; the agent's true root secret
is the Dilithium2 PQC key (quantum-resistant).

## Install

```bash
npm install aegis-chain-sol
```

## Usage

```js
import { deriveSolWallet, deriveSolWalletFromPQC, signMessage, verifyMessage } from 'aegis-chain-sol';

// From a 32-byte seed:
const wallet = deriveSolWallet(Buffer.alloc(32, 0x11));
console.log(wallet.address); // base58, e.g. "6PTLJh1AkMM..."

// From a PQC private key (quantum-resistant root):
const sol = deriveSolWalletFromPQC(pqcPrivateKey);

// Sign / verify (ed25519) — consistent with chain-eth, use privateKeyHex:
const sig = signMessage('hello', Buffer.from(sol.privateKeyHex, 'hex')); // 64 bytes
verifyMessage('hello', sig, Buffer.from(sol.publicKeyHex, 'hex')); // true
```

## API

- `deriveSolPrivateKey(seed)` — domain-separated HKDF → 32-byte ed25519 key
- `deriveSolWallet(seed)` → `{ privateKeyHex, publicKeyHex, address, keypair }`
- `deriveSolWalletFromPQC(pqcPrivateKey)` → SOL wallet from a Dilithium2 key
- `signMessage(message, privateKey)` / `verifyMessage(message, sig, publicKey)`
- `addressFromPublicKey(pubkey)` / `publicKeyFromAddress(address)`

> `privateKeyHex` is the preferred signing key — identical shape to
> `chain-eth`'s `deriveEthWallet`. `keypair` (64-byte Buffer) is retained for
> backward compatibility.

## Concept

```
PQC root key (Dilithium2, FIPS 204)
   │  sha256 → 32-byte seed
   ▼
HKDF('nexus/chain/sol/v1') → ed25519 private key → base58 address
```

## License

MIT