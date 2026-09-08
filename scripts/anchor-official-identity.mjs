/**
 * Anchor the OFFICIAL aegis-vault agent identity on ERC-8004 (Sepolia).
 *
 * Purpose (anti-impersonation): anyone can copy the code — nobody can copy
 * this on-chain identity. The registered agent carries:
 *   - an ML-DSA-44 (PQC) root fingerprint binding the identity to key material
 *   - a KYA commitment over {registry, agentId, kyaUri, policy, audit head}
 *   - an agentWallet registration pointing at the OFFICIAL SmartAccount
 *     deployed in the Stage-1 settlement evidence run
 *
 * Runbook: docs/runbook/ERC8004-ANCHORING.md
 *   node scripts/anchor-official-identity.mjs            # dry-run (no tx)
 *   node scripts/anchor-official-identity.mjs --execute  # real chain txs
 *
 * Requires: OWNER_PRIVATE_KEY env (funded Sepolia EOA), or falls back to the
 * milestone-4 secrets file. Writes docs/kya/AGENT-KYA.json on success.
 */
import fs from 'node:fs';
import path from 'node:path';
import { ethers } from 'ethers';
import {
  METADATA_KEYS,
  agentRegistryString,
  buildAgentRegistration,
  kyaCommitment,
  toDataUri,
} from 'aegis-erc8004';
import {
  IdentityRegistryClient,
  REGISTRY_PRESETS,
} from 'aegis-erc8004/clients';
import { generateKeyPair } from 'aegis-vault';

const CHAIN_ID = 11155111;
const RPC_URL = process.env.CHAIN_RPC_URL || 'https://ethereum-sepolia-rpc.publicnode.com';
const EXECUTE = process.argv.includes('--execute');
const SECRETS_FILE = 'C:/Users/f0tro/.secrets/aegis-identity-pqc.json';
const SMART_ACCOUNT = '0xa6cbdab1fae815c8578bff3c06df66c1f976ea36'; // Stage-1 settlement evidence
const KYA_URI = 'https://raw.githubusercontent.com/nexus-genesis/aegis-vault/main/docs/kya/AGENT-KYA.json';
// v0 audit chain: no full chain implementation yet (Stage 2+). The genesis
// head is honest — "empty chain" — and every future head derives from it.
const AUDIT_GENESIS_HEAD = ethers.keccak256(ethers.toUtf8Bytes('aegis/audit-chain/v1:genesis'));

function loadOwnerPk() {
  if (process.env.OWNER_PRIVATE_KEY) return process.env.OWNER_PRIVATE_KEY;
  return JSON.parse(fs.readFileSync('C:/Users/f0tro/.secrets/sepolia-milestone4.json', 'utf8')).OWNER.privateKey;
}

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const wallet = new ethers.Wallet(loadOwnerPk(), provider);
  const bal = ethers.formatEther(await provider.getBalance(wallet.address));
  console.log(`[identity] owner=${wallet.address} balance=${bal} ETH execute=${EXECUTE}`);

  // ── 1. PQC root keypair (persisted outside git for verifiable re-derivation)
  let pqc;
  if (fs.existsSync(SECRETS_FILE)) {
    pqc = JSON.parse(fs.readFileSync(SECRETS_FILE, 'utf8'));
    console.log('[identity] PQC root loaded from secrets file');
  } else {
    const kp = await generateKeyPair(); // ML-DSA-44
    pqc = {
      publicKey: Buffer.from(kp.publicKey).toString('hex'),
      privateKey: Buffer.from(kp.privateKey).toString('hex'),
      createdAt: new Date().toISOString(),
    };
    if (EXECUTE) {
      fs.mkdirSync(path.dirname(SECRETS_FILE), { recursive: true });
      fs.writeFileSync(SECRETS_FILE, JSON.stringify(pqc, null, 2));
      console.log(`[identity] PQC root generated + persisted to ${SECRETS_FILE}`);
    } else {
      console.log('[identity] PQC root generated (dry-run: NOT persisted)');
    }
  }
  const ownerFingerprint = ethers.keccak256('0x' + pqc.publicKey);

  // ── 2. Session policy commitment (the guardrail display defaults)
  const sessionPolicy = { type: 'limit', maxPerTx: '100', maxDaily: '500', timelock: '24h', mode: 'tiered' };
  const sessionPolicyHash = ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(sessionPolicy)));

  console.log(`[identity] ownerFingerprint=${ownerFingerprint}`);
  console.log(`[identity] sessionPolicyHash=${sessionPolicyHash}`);
  console.log(`[identity] auditChainHead=${AUDIT_GENESIS_HEAD} (v0 genesis)`);

  const registryStr = agentRegistryString(CHAIN_ID, REGISTRY_PRESETS.sepolia.identityRegistry);

  if (!EXECUTE) {
    const bundle = { agentRegistry: registryStr, agentId: '<minted>', kyaUri: KYA_URI, ownerFingerprint, sessionPolicyHash, auditChainHead: AUDIT_GENESIS_HEAD };
    console.log(`\n[dry-run] commitment would be: ${kyaCommitment({ ...bundle, agentId: 1 })}`);
    console.log('[dry-run] Would: register() -> setCommitment(KYA) -> setAgentWallet(0xa6cb…ea36)');
    console.log('[dry-run] Re-run with --execute to anchor for real.');
    return;
  }

  const client = new IdentityRegistryClient({
    signerOrProvider: wallet,
    addressOrPreset: REGISTRY_PRESETS.sepolia,
    chainId: CHAIN_ID,
  });

  if (process.argv.includes('--wallet-only')) {
    const agentId = BigInt(process.argv[process.argv.indexOf('--wallet-only') + 1]);
    // ERC-8004 agentWallet semantics: the signature must come FROM newWallet
    // (proof of consent), not from the agentId owner. Contracts need ERC-1271
    // (SmartAccount doesn't implement it yet) — so bind the owner EOA here;
    // upgrade to SmartAccount once it speaks ERC-1271.
    const deadline = Math.floor(Date.now() / 1000) + 3600;
    const walletTx = await client.setAgentWallet(agentId, wallet.address, deadline, wallet);
    console.log(`[identity] agentId=${agentId} agentWallet=${wallet.address} bound tx=${walletTx}`);
    return;
  }

  // ── 3. register (metadata: audit head; commitment follows in step 4)
  const provisional = buildAgentRegistration({
    name: 'aegis-vault official',
    description: 'Official aegis-vault guardrail agent identity. Non-custodial authorization guardrails for agent payments: tiered spend controls, human takeover, signed authorization snapshots. This on-chain identity is the anti-impersonation root for all official deployments.',
    services: [
      { name: 'guardrail-x402', endpoint: 'https://www.npmjs.com/package/aegis-guardrail-x402' },
      { name: 'guardrail-ap2', endpoint: 'https://www.npmjs.com/package/aegis-guardrail-ap2' },
    ],
    registrations: [{ agentId: 0, agentRegistry: registryStr }],
  });
  const agentId = await client.register(toDataUri(provisional), [
    { key: METADATA_KEYS.AUDIT_CHAIN_HEAD, value: AUDIT_GENESIS_HEAD },
  ]);
  console.log(`[identity] registered agentId=${agentId.toString()}`);

  // ── 4. KYA commitment over the full bundle (agentId now known)
  const commitment = kyaCommitment({
    agentRegistry: registryStr,
    agentId,
    kyaUri: KYA_URI,
    ownerFingerprint,
    sessionPolicyHash,
    auditChainHead: AUDIT_GENESIS_HEAD,
  });
  const commitmentTx = await client.setCommitment(agentId, METADATA_KEYS.KYA_COMMITMENT, commitment);
  console.log(`[identity] KYA commitment anchored tx=${commitmentTx}`);

  // ── 5. bind the OFFICIAL SmartAccount as agent wallet (EIP-712, owner-signed)
  const deadline = Math.floor(Date.now() / 1000) + 3600;
  const walletTx = await client.setAgentWallet(agentId, SMART_ACCOUNT, deadline, wallet);
  console.log(`[identity] agentWallet=${SMART_ACCOUNT} bound tx=${walletTx}`);

  // ── 6. emit KYA report for docs/kya/AGENT-KYA.json
  const bundle = {
    agentRegistry: registryStr,
    agentId: agentId.toString(),
    kyaUri: KYA_URI,
    ownerFingerprint,
    sessionPolicy,
    sessionPolicyHash,
    auditChainHead: AUDIT_GENESIS_HEAD,
    auditChainNote: 'v0 genesis head — per-snapshot chain lives in aegis-guardrail-x402; full audit chain is a Stage-2+ deliverable',
    commitment,
    agentWallet: SMART_ACCOUNT,
    transactions: { register: '<see RPC>', commitment: commitmentTx, agentWallet: walletTx },
    ownerAddress: wallet.address,
    network: 'sepolia (chainId 11155111)',
    anchoredAt: new Date().toISOString(),
  };
  fs.mkdirSync('docs/kya', { recursive: true });
  fs.writeFileSync('docs/kya/AGENT-KYA.json', JSON.stringify(bundle, null, 2) + '\n');
  console.log('\n[identity] KYA report written to docs/kya/AGENT-KYA.json — commit it so kyaUri resolves.');
  console.log(`[identity] commitment=${commitment}`);
}

main().catch((e) => { console.error('FAILED:', e.message); process.exit(1); });
