/**
 * aegis-chain-adapters —multi-chain address registry
 *
 * One PQC root identity →addresses on every supported chain:
 *   - Aegis Vault native: ng1 + Base58 (Dilithium2)
 *   - Ethereum:            secp256k1 →EIP-55 address (HKDF derived)
 *   - Solana:              ed25519 →base58 address (HKDF derived)
 *
 * The PQC Dilithium2 key is the root; ETH/SOL keys are deterministic
 * secondary derivations. No private material is ever emitted by registry — * only addresses and public keys.
 */
import { generateAddress, hash } from 'aegis-vault';
import { deriveEthWalletFromPQC } from 'aegis-chain-eth';
import { deriveSolWalletFromPQC } from 'aegis-chain-sol';

export const SUPPORTED_CHAINS = ['nexus', 'eth', 'sol'];

/**
 * Derive addresses on all supported chains from a PQC key pair.
 * @param {Buffer} pqcPublicKey  Dilithium2 public key
 * @param {Buffer} pqcPrivateKey Dilithium2 private key
 * @returns {{ nexus: string, eth: string, sol: string }}
 */
export function deriveChainAddresses(pqcPublicKey, pqcPrivateKey) {
  const nexus = generateAddress(pqcPublicKey);
  const eth = deriveEthWalletFromPQC(pqcPrivateKey).address;
  const sol = deriveSolWalletFromPQC(pqcPrivateKey).address;
  return { nexus, eth, sol };
}

/**
 * Derive a single-chain address from a PQC key pair.
 * @param {'nexus'|'eth'|'sol'} chain
 * @param {Buffer} pqcPublicKey
 * @param {Buffer} pqcPrivateKey
 * @returns {string}
 */
export function deriveChainAddress(chain, pqcPublicKey, pqcPrivateKey) {
  switch (chain) {
    case 'nexus':
      return generateAddress(pqcPublicKey);
    case 'eth':
      return deriveEthWalletFromPQC(pqcPrivateKey).address;
    case 'sol':
      return deriveSolWalletFromPQC(pqcPrivateKey).address;
    default:
      throw new Error(`Unsupported chain: ${chain}`);
  }
}

/**
 * Compute a stable agent fingerprint from the PQC public key.
 * @param {Buffer} pqcPublicKey
 * @returns {string} sha256 hex
 */
export function deriveAgentFingerprint(pqcPublicKey) {
  return hash(pqcPublicKey, 'sha256');
}

export default {
  SUPPORTED_CHAINS,
  deriveChainAddresses,
  deriveChainAddress,
  deriveAgentFingerprint
};