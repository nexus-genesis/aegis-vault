/**
 * aegis-erc8004 — ERC-8004 (Trustless Agents) binding
 *
 * Positioning (docs/strategy/PRODUCT-POSITIONING-v0.2.md §03): "绑定标准，
 * 不重定义". ERC-8004 owns agent identity (ERC-721 Identity Registry) and
 * validation hooks. This package does NOT reinvent identity — it produces
 * ERC-8004-compliant artifacts and anchors Aegis KYA (Know-Your-Agent)
 * commitments INTO the standard's surfaces:
 *
 *   1. buildAgentRegistration()  → spec-compliant registration file
 *      (type: eip-8004#registration-v1) with the Aegis binding expressed as
 *      a custom service entry ("aegis" endpoint) — the spec explicitly
 *      allows arbitrary service names/endpoints.
 *   2. kyaCommitment()           → keccak256 commitment over the canonical
 *      KYA bundle (agent registry identity, owner fingerprint, session
 *      policy hash, audit chain head). Commitment (not data) so nothing
 *      sensitive lands on-chain.
 *   3. On-chain anchoring happens via the Identity Registry's standard
 *      setMetadata() hook (keys "aegis.kya.commitment" / "aegis.audit.head")
 *      and the Validation Registry's validationRequest() hook — see
 *      ./clients.js.
 *
 * Spec basis: EIP-8004 Jan 2026 (v1.2). ABI/typed-data details that the
 * spec leaves to implementations follow the reference deployment and are
 * overridable — never silently guessed.
 */
import { keccak256, toUtf8Bytes, encodeBase64 } from 'ethers';

export const REGISTRATION_TYPE = 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1';

/** On-chain metadata keys reserved by the Aegis binding (set via setMetadata). */
export const METADATA_KEYS = {
  KYA_COMMITMENT: 'aegis.kya.commitment',   // bytes32: kyaCommitment() output
  AUDIT_CHAIN_HEAD: 'aegis.audit.head'      // bytes32: audit hash-chain head
};

/** Custom service entry used to advertise the KYA surface in the registration file. */
export const AEGIS_SERVICE_NAME = 'aegis';

export const KYA_COMMITMENT_VERSION = 1;

/**
 * Deterministic JSON serialization (stable key order) so commitments are
 * reproducible across processes and verifiable without JSON-impl quirks.
 */
export function canonicalize(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return `[${obj.map(canonicalize).join(',')}]`;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(obj[k])}`).join(',')}}`;
}

/**
 * ERC-8004 agentRegistry string: "{namespace}:{chainId}:{identityRegistry}".
 * @example agentRegistryString(11155111, '0xf66e...') // 'eip155:11155111:0xf66e...'
 */
export function agentRegistryString(chainId, identityRegistry, namespace = 'eip155') {
  if (!Number.isInteger(chainId) || chainId <= 0) {
    throw new TypeError('chainId must be a positive integer');
  }
  if (typeof identityRegistry !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(identityRegistry)) {
    throw new TypeError('identityRegistry must be a 20-byte hex address');
  }
  return `${namespace}:${chainId}:${identityRegistry.toLowerCase()}`;
}

/**
 * Build an ERC-8004-compliant agent registration file.
 *
 * @param {object} input
 * @param {string} input.name required
 * @param {string} input.description required
 * @param {Array<{name:string, endpoint:string, version?:string}>} input.services
 *   endpoint services (A2A, MCP, web, ...). The Aegis service is appended.
 * @param {boolean} [input.x402Support=false]
 * @param {Array<{agentId:number|string, agentRegistry:string}>} input.registrations
 * @param {string[]} [input.supportedTrust] e.g. ['reputation','crypto-economic']
 * @param {string} [input.image]
 * @param {string} [input.kyaUri] HTTPS URI where the human-readable KYA report
 *   lives. Required together with kyaCommitment — a binding you cannot fetch
 *   is not a binding.
 * @param {string} [input.kyaCommitment] 32-byte hex from kyaCommitment().
 * @returns {object} registration file (JSON-serializable, key order normalized
 *   by callers via JSON.stringify — commitment hashing never depends on it).
 */
export function buildAgentRegistration(input = {}) {
  const {
    name, description, image, services, x402Support = false,
    registrations, supportedTrust, kyaUri, kyaCommitment
  } = input;

  if (!name || typeof name !== 'string') throw new TypeError('name is required');
  if (!description || typeof description !== 'string') throw new TypeError('description is required');
  if (!Array.isArray(services) || services.length === 0) {
    throw new TypeError('services[] required — an agent with no reachable endpoints is undiscoverable');
  }
  for (const s of services) {
    if (!s || typeof s.name !== 'string' || typeof s.endpoint !== 'string' || !s.endpoint) {
      throw new TypeError('each service needs { name, endpoint }');
    }
  }
  if (!Array.isArray(registrations) || registrations.length === 0) {
    throw new TypeError('registrations[] required — the spec: agents SHOULD have at least one registration');
  }
  for (const r of registrations) {
    if (!r || r.agentId == null || typeof r.agentRegistry !== 'string' || !r.agentRegistry) {
      throw new TypeError('each registration needs { agentId, agentRegistry }');
    }
  }
  const hasBinding = kyaUri != null || kyaCommitment != null;
  if (hasBinding && (typeof kyaUri !== 'string' || !kyaUri)) {
    throw new TypeError('kyaCommitment without kyaUri — a binding you cannot fetch is not a binding');
  }
  if (kyaCommitment != null && !/^0x[0-9a-f]{64}$/.test(kyaCommitment)) {
    throw new TypeError('kyaCommitment must be a 32-byte hex value');
  }

  const file = {
    type: REGISTRATION_TYPE,
    name,
    description,
    services: [...services],
    x402Support: Boolean(x402Support),
    active: true,
    registrations: registrations.map((r) => ({ agentId: r.agentId, agentRegistry: r.agentRegistry }))
  };
  if (image) file.image = image;
  if (Array.isArray(supportedTrust) && supportedTrust.length > 0) {
    file.supportedTrust = [...supportedTrust];
  }
  if (hasBinding) {
    // Commitment anchoring is primarily on-chain (setMetadata via clients.js);
    // embedding it here too keeps the file self-contained for offline audits.
    file.services.push({
      name: AEGIS_SERVICE_NAME,
      endpoint: kyaUri,
      version: String(KYA_COMMITMENT_VERSION),
      ...(kyaCommitment ? { kyaCommitment } : {})
    });
  }
  return file;
}

/**
 * Compute the Aegis KYA commitment: keccak256 over the canonical bundle.
 * On-chain only the commitment lands; the bundle itself lives off-chain
 * (kyaUri). Changing ANY bundle component invalidates the commitment —
 * that is the point.
 *
 * @param {object} bundle
 * @param {string} bundle.agentRegistry 'eip155:{chainId}:{identityRegistry}'
 * @param {number|string} bundle.agentId ERC-721 tokenId
 * @param {string} bundle.kyaUri where the full KYA bundle / report is served
 * @param {string} bundle.ownerFingerprint hex fingerprint of the human owner's
 *   key material (e.g. keccak of the PQC root public key)
 * @param {string} bundle.sessionPolicyHash commitment to the active session
 *   policy (limits, scopes, timelock)
 * @param {string} bundle.auditChainHead current head of the audit hash chain
 * @returns {string} 32-byte hex commitment
 */
export function kyaCommitment(bundle = {}) {
  const { agentRegistry, agentId, kyaUri, ownerFingerprint, sessionPolicyHash, auditChainHead } = bundle;
  for (const [k, v] of Object.entries({ agentRegistry, kyaUri, ownerFingerprint, sessionPolicyHash, auditChainHead })) {
    if (typeof v !== 'string' || !v) throw new TypeError(`kyaCommitment: ${k} is required`);
  }
  if (agentId == null) throw new TypeError('kyaCommitment: agentId is required');
  const preimage = canonicalize({
    v: KYA_COMMITMENT_VERSION,
    agentRegistry,
    agentId: String(agentId),
    kyaUri,
    ownerFingerprint,
    sessionPolicyHash,
    auditChainHead
  });
  return keccak256(toUtf8Bytes(preimage));
}

/**
 * Encode a JSON object as the base64 data: URI form the spec allows for
 * fully on-chain metadata (agentURI = "data:application/json;base64,...").
 */
export function toDataUri(registrationFile) {
  const json = JSON.stringify(registrationFile);
  return `data:application/json;base64,${encodeBase64(toUtf8Bytes(json))}`;
}

/**
 * Verify that an ERC-8004 registration file actually carries the Aegis
 * binding we expect. Used by verifiers (wallets, auditors, insurers) that
 * consume an agent's registration before trusting its guardrail claims.
 *
 * @param {object} file parsed registration file
 * @param {object} expected
 * @param {string} expected.agentRegistry
 * @param {number|string} [expected.agentId] if omitted, any listed id passes
 * @param {string} [expected.kyaUri] if omitted, presence of the aegis service
 *   is enough; if provided it must match exactly
 * @param {string} [expected.kyaCommitment] if provided, must match the
 *   commitment recomputed from the KYA bundle (pass bundle to recompute)
 * @param {object} [expected.kyaBundle] bundle for kyaCommitment() recompute
 * @returns {{ ok: boolean, errors: string[] }}
 */
export function verifyBinding(file, expected = {}) {
  const errors = [];
  if (!file || typeof file !== 'object') return { ok: false, errors: ['registration file missing'] };
  if (file.type !== REGISTRATION_TYPE) errors.push('type is not eip-8004#registration-v1');
  if (file.active !== true) errors.push('registration is not active');

  const regs = Array.isArray(file.registrations) ? file.registrations : [];
  const matchesRegistry = regs.some((r) => r && r.agentRegistry === expected.agentRegistry
    && (expected.agentId == null || String(r.agentId) === String(expected.agentId)));
  if (!expected.agentRegistry) errors.push('expected.agentRegistry is required to verify');
  else if (!matchesRegistry) errors.push('no registration entry matches the expected registry/agentId');

  const aegisSvc = (file.services || []).find((s) => s && s.name === AEGIS_SERVICE_NAME);
  if (!aegisSvc) {
    errors.push(`no "${AEGIS_SERVICE_NAME}" service entry — agent does not advertise a KYA surface`);
  } else if (expected.kyaUri && aegisSvc.endpoint !== expected.kyaUri) {
    errors.push('aegis service endpoint does not match the expected kyaUri');
  }

  if (expected.kyaCommitment && expected.kyaBundle) {
    const recomputed = kyaCommitment({ ...expected.kyaBundle, agentRegistry: expected.agentRegistry, agentId: expected.agentId ?? expected.kyaBundle.agentId });
    if (recomputed !== expected.kyaCommitment) errors.push('kyaCommitment does not match the provided KYA bundle');
  }
  return { ok: errors.length === 0, errors };
}
