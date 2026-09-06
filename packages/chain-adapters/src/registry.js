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
import { generateAddress, hash, deriveDomainSeed, DERIVATION_DOMAINS, DERIVATION_VERSION } from 'aegis-vault';
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

// ── v2: root→chain domain-separated derivation (PHASE2 audit) ─────────────

/**
 * v2 chain derivation: the PQC root secret is first bound to an explicit
 * 'chain-key' PURPOSE domain (per chain), and only then handed to the chain
 * adapter's internal HKDF. This closes the root→sub domain-separation gap of
 * v1, where the raw PQC private key entered every chain's HKDF directly.
 *
 * v1 (default) is kept byte-for-byte: existing addresses must never change.
 * New deployments should use the V2 functions and record derivationVersion=2
 * alongside the agent identity.
 */

/**
 * Derive a v2 domain seed for one chain from the PQC private key.
 * @param {Buffer} pqcPrivateKey
 * @param {'eth'|'sol'} chain
 * @returns {Promise<Buffer>} 32-byte chain domain seed
 */
export async function deriveChainDomainSeed(pqcPrivateKey, chain) {
  if (!pqcPrivateKey || Buffer.from(pqcPrivateKey).length !== 32) {
    throw new Error(`Invalid PQC private key: expected 32 bytes, got ${pqcPrivateKey ? Buffer.from(pqcPrivateKey).length : 0}`);
  }
  return deriveDomainSeed(Buffer.from(pqcPrivateKey), {
    domain: DERIVATION_DOMAINS.CHAIN_KEY,
    chain,
    version: DERIVATION_VERSION
  });
}

/**
 * v2: derive a single-chain address with root→chain domain separation.
 * @param {'eth'|'sol'} chain
 * @param {Buffer} pqcPrivateKey
 * @returns {Promise<string>}
 */
export async function deriveChainAddressV2(chain, pqcPrivateKey) {
  const seed = await deriveChainDomainSeed(pqcPrivateKey, chain);
  switch (chain) {
    case 'eth':
      return deriveEthWalletFromPQC(seed).address;
    case 'sol':
      return deriveSolWalletFromPQC(seed).address;
    default:
      throw new Error(`v2 derivation unsupported for chain: ${chain}`);
  }
}

/**
 * v2: derive addresses on all domain-separated chains.
 * @param {Buffer} pqcPrivateKey
 * @returns {Promise<{ eth: string, sol: string }>}
 */
export async function deriveChainAddressesV2(pqcPrivateKey) {
  const [eth, sol] = await Promise.all([
    deriveChainAddressV2('eth', pqcPrivateKey),
    deriveChainAddressV2('sol', pqcPrivateKey)
  ]);
  return { eth, sol };
}

export default {
  SUPPORTED_CHAINS,
  DERIVATION_VERSION,
  deriveChainAddresses,
  deriveChainAddress,
  deriveAgentFingerprint,
  deriveChainDomainSeed,
  deriveChainAddressV2,
  deriveChainAddressesV2
};