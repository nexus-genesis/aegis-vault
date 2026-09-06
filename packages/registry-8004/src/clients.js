/**
 * aegis-registry-8004/clients — thin ERC-8004 registry clients (ethers v6)
 *
 * Deliberately thin: the standard owns identity and validation. These
 * clients exist to (a) mint/register agents, (b) push Aegis commitments
 * through the spec's setMetadata() hook, and (c) request KYA validation
 * through the Validation Registry hook.
 *
 * Contract addresses are ALWAYS caller-supplied or taken from the presets
 * below (community reference deployments). The preset format is
 * documented in docs/runbook/ERC8004-ANCHORING.md — never hardcode a
 * "canonical" address without a source you can link.
 */
import { Contract } from 'ethers';

/**
 * ABI fragments per EIP-8004 Jan 2026 (v1.2). Overridable per-instance:
 * the spec is fresh and fragments may be revised — pass `abi` in options
 * rather than forking this file.
 */
export const IDENTITY_REGISTRY_ABI = [
  'function register(string agentURI) returns (uint256 agentId)',
  'function register(string agentURI, (string metadataKey, bytes metadataValue)[] metadata) returns (uint256 agentId)',
  'function setAgentURI(uint256 agentId, string newURI)',
  'function setMetadata(uint256 agentId, string metadataKey, bytes metadataValue)',
  'function getMetadata(uint256 agentId, string metadataKey) view returns (bytes)',
  'function setAgentWallet(uint256 agentId, address newWallet, uint256 deadline, bytes signature)',
  'function getAgentWallet(uint256 agentId) view returns (address)',
  'function ownerOf(uint256 agentId) view returns (address)',
  'function tokenURI(uint256 agentId) view returns (string)',
  'event Registered(uint256 indexed agentId, string agentURI, address indexed owner)',
  'event URIUpdated(uint256 indexed agentId, string newURI, address indexed updatedBy)',
  'event MetadataSet(uint256 indexed agentId, string indexed indexedMetadataKey, string metadataKey, bytes metadataValue)'
];

export const VALIDATION_REGISTRY_ABI = [
  'function validationRequest(uint256 agentId, address validatorAddress, string dataURI) returns (bytes32 requestHash)',
  'function validationResponse(bytes32 requestHash, uint8 score, string responseURI, bytes32 responseHash)',
  'function getValidationStatus(bytes32 requestHash) view returns (uint256 agentId, address validatorAddress, bool isSet, uint256 lastUpdateInBlock, uint8 score, bytes32 responseHash)',
  'event ValidationRequested(uint256 indexed agentId, address indexed validatorAddress, bytes32 indexed requestHash, string dataURI)',
  'event ValidationResponse(bytes32 indexed requestHash, address indexed validatorAddress, uint256 indexed agentId, uint8 score, string responseURI, bytes32 responseHash)'
];

/**
 * Community reference deployments (ChaosChain RI, Jan 2026 spec, Sepolia).
 * Verify against the current reference implementation before production use;
 * per-chain singleton addresses must always be linked to their source.
 */
export const REGISTRY_PRESETS = {
  sepolia: {
    chainId: 11155111,
    namespace: 'eip155',
    identityRegistry: '0xf66e7CBdAE1Cb710fee7732E4e1f173624e137A7',
    reputationRegistry: '0x6E2a285294B5c74CB76d76AB77C1ef15c2A9E407',
    source: 'github.com/ChaosChain/trustless-agents-erc-ri (Jan 2026 spec deployment)'
  }
};

function resolveAddress(addressOrPreset) {
  if (typeof addressOrPreset === 'string') return { address: addressOrPreset, chainId: null };
  if (addressOrPreset && typeof addressOrPreset === 'object' && addressOrPreset.identityRegistry) {
    return { address: addressOrPreset.identityRegistry, chainId: addressOrPreset.chainId ?? null };
  }
  throw new TypeError('provide a contract address or a REGISTRY_PRESETS entry');
}

/**
 * Identity Registry client.
 *
 * @param {object} options
 * @param {ethers.Signer|ethers.Provider} options.signerOrProvider signer for
 *   transactions, provider for read-only use
 * @param {string|object} options.addressOrPreset contract address or preset
 * @param {string[]} [options.abi] override IDENTITY_REGISTRY_ABI
 */
export class IdentityRegistryClient {
  constructor({ signerOrProvider, addressOrPreset, abi, chainId } = {}) {
    const resolved = resolveAddress(addressOrPreset);
    this.address = resolved.address;
    this.chainId = chainId ?? resolved.chainId;
    if (!this.chainId) {
      throw new TypeError('chainId is required for EIP-712 domain construction (or use a preset)');
    }
    this.contract = new Contract(this.address, abi ?? IDENTITY_REGISTRY_ABI, signerOrProvider);
  }

  /** register() with the standard metadata overload; returns the agentId. */
  async register(agentURI, metadataEntries = []) {
    const entries = metadataEntries.map((e) => ({ metadataKey: e.key, metadataValue: e.value }));
    if (entries.length === 0) {
      const tx = await this.contract.register(agentURI);
      const rc = await tx.wait();
      return this._extractAgentId(rc);
    }
    const tx = await this.contract.register(agentURI, entries);
    const rc = await tx.wait();
    return this._extractAgentId(rc);
  }

  _extractAgentId(receipt) {
    // Registered(uint256 indexed agentId, string agentURI, address indexed owner)
    for (const log of receipt.logs ?? []) {
      try {
        const parsed = this.contract.interface.parseLog(log);
        if (parsed && parsed.name === 'Registered') return parsed.args.agentId;
      } catch { /* foreign log */ }
    }
    throw new Error('Registered event not found in receipt — aborting instead of guessing the agentId');
  }

  async setAgentURI(agentId, newURI) {
    return (await (await this.contract.setAgentURI(agentId, newURI)).wait()).hash;
  }

  /**
   * Anchor a 32-byte hex commitment (e.g. METADATA_KEYS.KYA_COMMITMENT) as
   * on-chain metadata. Only bytes32 values are accepted by this helper —
   * freeform metadata should think twice before landing on-chain.
   */
  async setCommitment(agentId, key, hex32) {
    if (!/^0x[0-9a-fA-F]{64}$/.test(hex32)) {
      throw new TypeError(`${key} must be a 32-byte hex value`);
    }
    return (await (await this.contract.setMetadata(agentId, key, hex32)).wait()).hash;
  }

  async getCommitment(agentId, key) {
    return this.contract.getMetadata(agentId, key);
  }

  /**
   * EIP-712 typed data for setAgentWallet's ownership proof. The EIP text
   * mandates EIP-712 but does not pin the message layout; this follows the
   * reference implementation and can be overridden per deployment.
   */
  agentWalletTypedData(agentId, newWallet, deadline, { name = 'Agent Wallet', version = '1', chainId, verifyingContract } = {}) {
    return {
      domain: {
        name, version,
        chainId: chainId ?? this.chainId,
        verifyingContract: verifyingContract ?? this.address
      },
      primaryType: 'AgentWallet',
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' }
        ],
        AgentWallet: [
          { name: 'agentId', type: 'uint256' },
          { name: 'wallet', type: 'address' },
          { name: 'deadline', type: 'uint256' }
        ]
      },
      message: { agentId: BigInt(agentId), wallet: newWallet, deadline: BigInt(deadline) }
    };
  }

  /** Sign + submit the agentWallet update (EOA path; ERC-1271 for contracts is caller-side). */
  async setAgentWallet(agentId, newWallet, deadline, signer) {
    const typed = this.agentWalletTypedData(agentId, newWallet, deadline);
    const signature = await signer.signTypedData(typed.domain, { AgentWallet: typed.types.AgentWallet }, typed.message);
    return (await (await this.contract.setAgentWallet(agentId, newWallet, deadline, signature)).wait()).hash;
  }
}

/**
 * Validation Registry client — the "anchoring" hook: request that an
 * independent validator attests the KYA bundle behind a commitment.
 *
 * @param {object} options same shape as IdentityRegistryClient; the preset's
 *   validationRegistry is intentionally absent — it had not shipped to the
 *   reference deployment at time of writing and must not be guessed.
 */
export class ValidationRegistryClient {
  constructor({ signerOrProvider, addressOrPreset, abi } = {}) {
    const { address } = resolveAddress(addressOrPreset);
    this.address = address;
    this.contract = new Contract(address, abi ?? VALIDATION_REGISTRY_ABI, signerOrProvider);
  }

  /** Request independent validation of `dataURI` for agentId by `validatorAddress`. */
  async requestValidation(agentId, validatorAddress, dataURI) {
    const tx = await this.contract.validationRequest(agentId, validatorAddress, dataURI);
    const rc = await tx.wait();
    for (const log of rc.logs ?? []) {
      try {
        const parsed = this.contract.interface.parseLog(log);
        if (parsed && parsed.name === 'ValidationRequested') return parsed.args.requestHash;
      } catch { /* foreign log */ }
    }
    throw new Error('ValidationRequested event not found — aborting instead of guessing the requestHash');
  }

  async status(requestHash) {
    return this.contract.getValidationStatus(requestHash);
  }
}
