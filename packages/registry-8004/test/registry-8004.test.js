/**
 * aegis-erc8004 — Stage 2 binding tests
 *
 * Scope: pure artifact construction + binding invariants + offline encoders.
 * No network is contacted — chain interaction is exercised in the runbook
 * (docs/runbook/ERC8004-ANCHORING.md) against a testnet.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ethers } from 'ethers';

import {
  REGISTRATION_TYPE,
  METADATA_KEYS,
  AEGIS_SERVICE_NAME,
  agentRegistryString,
  buildAgentRegistration,
  kyaCommitment,
  toDataUri,
  verifyBinding,
  canonicalize
} from '../src/index.js';
import {
  IdentityRegistryClient,
  ValidationRegistryClient,
  REGISTRY_PRESETS
} from '../src/clients.js';

const SEPOLIA_IR = REGISTRY_PRESETS.sepolia.identityRegistry;
const CHAIN_ID = REGISTRY_PRESETS.sepolia.chainId;

// ─── agentRegistryString ─────────────────────────────────────────────────
test('agentRegistryString formats per spec and normalizes address case', () => {
  const s = agentRegistryString(11155111, '0xF66E7CBdAE1Cb710fee7732E4e1f173624e137A7');
  assert.equal(s, 'eip155:11155111:0xf66e7cbdae1cb710fee7732e4e1f173624e137a7');
  assert.throws(() => agentRegistryString(0, SEPOLIA_IR), TypeError);
  assert.throws(() => agentRegistryString(1, 'not-an-address'), TypeError);
});

// ─── buildAgentRegistration ──────────────────────────────────────────────
const BASE = {
  name: 'acme-purchasing-agent',
  description: 'Procurement agent authorized to spend up to tiered limits',
  services: [{ name: 'web', endpoint: 'https://agent.acme.example/' }],
  registrations: [{ agentId: 22, agentRegistry: agentRegistryString(CHAIN_ID, SEPOLIA_IR) }],
  supportedTrust: ['reputation']
};

test('[CRITICAL] registration file is spec-compliant in shape', () => {
  const file = buildAgentRegistration(BASE);
  assert.equal(file.type, REGISTRATION_TYPE);
  assert.equal(file.active, true);
  assert.equal(file.x402Support, false);
  assert.equal(file.registrations[0].agentId, 22);
  assert.ok(!('supportedTrust' in file) === false, 'supportedTrust carried when provided');
});

test('aegis service entry tracks kyaUri; commitment embeds when present', () => {
  // URI alone is a valid binding surface (commitment anchors on-chain separately)
  const file = buildAgentRegistration({ ...BASE, kyaUri: 'https://kya.acme.example/22' });
  const svc = file.services.find((s) => s.name === AEGIS_SERVICE_NAME);
  assert.equal(svc.endpoint, 'https://kya.acme.example/22');
  assert.equal(svc.kyaCommitment, undefined);

  const file2 = buildAgentRegistration({
    ...BASE,
    kyaUri: 'https://kya.acme.example/22',
    kyaCommitment: '0x' + 'ab'.repeat(32)
  });
  const svc2 = file2.services.find((s) => s.name === AEGIS_SERVICE_NAME);
  assert.equal(svc2.kyaCommitment, '0x' + 'ab'.repeat(32));
  assert.equal(file2.services.length, BASE.services.length + 1, 'binding is additive, not replacing standard services');
});

test('malformed inputs fail closed (no half-valid registration files)', () => {
  assert.throws(() => buildAgentRegistration({ ...BASE, services: [] }), TypeError);
  assert.throws(() => buildAgentRegistration({ ...BASE, registrations: [] }), TypeError);
  assert.throws(() => buildAgentRegistration({ ...BASE, services: [{ name: 'web' }] }), TypeError);
  assert.throws(() => buildAgentRegistration({ ...BASE, kyaUri: 'https://x', kyaCommitment: '0x1234' }), TypeError);
});

// ─── kyaCommitment ───────────────────────────────────────────────────────
const BUNDLE = {
  agentRegistry: agentRegistryString(CHAIN_ID, SEPOLIA_IR),
  agentId: 22,
  kyaUri: 'https://kya.acme.example/22',
  ownerFingerprint: '0x' + '11'.repeat(32),
  sessionPolicyHash: '0x' + '22'.repeat(32),
  auditChainHead: '0x' + '33'.repeat(32)
};

test('[CRITICAL] kyaCommitment is deterministic and binds every component', () => {
  const a = kyaCommitment(BUNDLE);
  const b = kyaCommitment({ ...BUNDLE });
  assert.equal(a, b, 'same bundle → same commitment');
  assert.match(a, /^0x[0-9a-f]{64}$/);

  // Any single component change must invalidate the commitment.
  for (const key of ['agentRegistry', 'kyaUri', 'ownerFingerprint', 'sessionPolicyHash', 'auditChainHead']) {
    const mutated = { ...BUNDLE, [key]: key === 'agentId' ? 23 : '0x' + 'ff'.repeat(32) };
    if (key === 'agentId') mutated.agentId = 23;
    assert.notEqual(kyaCommitment(mutated), a, `commitment must bind ${key}`);
  }
  assert.notEqual(kyaCommitment({ ...BUNDLE, agentId: 23 }), a, 'commitment must bind agentId');
});

test('kyaCommitment rejects incomplete bundles (fail-closed)', () => {
  for (const key of Object.keys(BUNDLE)) {
    const broken = { ...BUNDLE };
    delete broken[key];
    assert.throws(() => kyaCommitment(broken), TypeError, `missing ${key} must throw`);
  }
});

// ─── verifyBinding ───────────────────────────────────────────────────────
test('verifyBinding accepts a correctly bound registration', () => {
  const commitment = kyaCommitment(BUNDLE);
  const file = buildAgentRegistration({
    ...BASE,
    kyaUri: BUNDLE.kyaUri,
    kyaCommitment: commitment
  });
  const result = verifyBinding(file, {
    agentRegistry: BUNDLE.agentRegistry,
    agentId: 22,
    kyaUri: BUNDLE.kyaUri,
    kyaCommitment: commitment,
    kyaBundle: BUNDLE
  });
  assert.deepEqual(result, { ok: true, errors: [] });
});

test('[HIGH] verifyBinding rejects look-alike registrations', () => {
  const commitment = kyaCommitment(BUNDLE);
  const file = buildAgentRegistration({ ...BASE, kyaUri: BUNDLE.kyaUri, kyaCommitment: commitment });

  // Wrong registry
  const wrongRegistry = verifyBinding(file, { agentRegistry: 'eip155:1:0x' + 'aa'.repeat(20), agentId: 22 });
  assert.equal(wrongRegistry.ok, false);
  assert.ok(wrongRegistry.errors.some((e) => /registry\/agentId/.test(e)));

  // Unbound agent (no aegis service)
  const unbound = buildAgentRegistration(BASE);
  const res2 = verifyBinding(unbound, { agentRegistry: BUNDLE.agentRegistry, agentId: 22 });
  assert.equal(res2.ok, false);
  assert.ok(res2.errors.some((e) => /KYA surface/.test(e)));

  // Tampered KYA bundle → commitment mismatch
  const tampered = verifyBinding(file, {
    agentRegistry: BUNDLE.agentRegistry,
    agentId: 22,
    kyaUri: BUNDLE.kyaUri,
    kyaCommitment: commitment,
    kyaBundle: { ...BUNDLE, sessionPolicyHash: '0x' + 'ee'.repeat(32) }
  });
  assert.equal(tampered.ok, false);
  assert.ok(tampered.errors.some((e) => /does not match/.test(e)));
});

// ─── data URI / canonicalize ─────────────────────────────────────────────
test('toDataUri roundtrips through base64 decode', () => {
  const file = buildAgentRegistration(BASE);
  const uri = toDataUri(file);
  assert.match(uri, /^data:application\/json;base64,/);
  const decoded = JSON.parse(Buffer.from(uri.split(',')[1], 'base64').toString('utf8'));
  assert.equal(decoded.name, file.name);
  assert.deepEqual(decoded.registrations, file.registrations);
});

test('canonicalize is order-stable', () => {
  assert.equal(canonicalize({ b: 1, a: 2 }), canonicalize({ a: 2, b: 1 }));
  assert.equal(canonicalize({ z: { y: 1, x: [2, { c: 3, d: 4 }] } }), canonicalize({ z: { x: [2, { d: 4, c: 3 }], y: 1 } }));
});

// ─── offline client encoders ─────────────────────────────────────────────
test('[CRITICAL] agentWalletTypedData is deterministic EIP-712 and signs over the right fields', () => {
  const client = new IdentityRegistryClient({
    signerOrProvider: new ethers.JsonRpcProvider('http://127.0.0.1:1'), // lazy: no connection attempted
    addressOrPreset: REGISTRY_PRESETS.sepolia,
    chainId: CHAIN_ID
  });
  const deadline = 1_900_000_000;
  const wallet = '0x1111111111111111111111111111111111111111';

  const t1 = client.agentWalletTypedData(22, wallet, deadline);
  const t2 = client.agentWalletTypedData(22, wallet, deadline);
  assert.deepEqual(t1, t2);
  // RI v1.2 reference contract domain + typehash (verified against the
  // deployed Sepolia IdentityRegistry source, 2026-09-08).
  assert.equal(t1.domain.name, 'ERC-8004 IdentityRegistry');
  assert.equal(t1.domain.version, '1.1');
  assert.equal(t1.primaryType, 'SetAgentWallet');
  assert.equal(t1.domain.verifyingContract, SEPOLIA_IR);
  assert.equal(t1.domain.chainId, CHAIN_ID);
  assert.equal(t1.message.agentId, 22n);
  assert.equal(t1.message.newWallet, wallet);

  const h1 = ethers.TypedDataEncoder.hash(t1.domain, { SetAgentWallet: t1.types.SetAgentWallet }, t1.message);
  // Changing the wallet or deadline must change the digest
  const h2 = ethers.TypedDataEncoder.hash(t1.domain, { SetAgentWallet: t1.types.SetAgentWallet }, { ...t1.message, deadline: deadline + 1 });
  const h3 = ethers.TypedDataEncoder.hash(
    t1.domain, { SetAgentWallet: t1.types.SetAgentWallet },
    { ...t1.message, newWallet: '0x2222222222222222222222222222222222222222' }
  );
  assert.notEqual(h1, h2);
  assert.notEqual(h1, h3);
  assert.match(h1, /^0x[0-9a-f]{64}$/);
});

test('client construction fails closed without chainId for EIP-712 use', () => {
  assert.throws(
    () => new IdentityRegistryClient({
      signerOrProvider: new ethers.JsonRpcProvider('http://127.0.0.1:1'),
      addressOrPreset: SEPOLIA_IR // raw address → no chainId available
    }),
    TypeError
  );
});

test('setCommitment enforces 32-byte values before any chain interaction', async () => {
  const client = new IdentityRegistryClient({
    signerOrProvider: new ethers.JsonRpcProvider('http://127.0.0.1:1'),
    addressOrPreset: REGISTRY_PRESETS.sepolia,
    chainId: CHAIN_ID
  });
  await assert.rejects(
    client.setCommitment(22, METADATA_KEYS.KYA_COMMITMENT, '0x1234'),
    TypeError
  );
  await assert.rejects(
    client.setCommitment(22, METADATA_KEYS.AUDIT_CHAIN_HEAD, 'not-hex'),
    TypeError
  );
});

test('register() extracts agentId from the Registered event, never guesses', async () => {
  const client = new IdentityRegistryClient({
    signerOrProvider: new ethers.JsonRpcProvider('http://127.0.0.1:1'),
    addressOrPreset: REGISTRY_PRESETS.sepolia,
    chainId: CHAIN_ID
  });
  const iface = client.contract.interface;
  // Encode a receipt-shaped log via the ABI (offline event parse path).
  const agentId = 4242n;
  const logData = iface.encodeEventLog(
    iface.getEvent('Registered'),
    [agentId, 'data:application/json;base64,e30=', '0x3333333333333333333333333333333333333333']
  );
  const fakeReceipt = { logs: [{ topics: logData.topics, data: logData.data }] };
  assert.equal(client._extractAgentId(fakeReceipt), agentId);
  assert.throws(() => client._extractAgentId({ logs: [] }), /Registered event not found/);
});

test('ValidationRegistryClient builds from preset validationRegistry and matches the RI v1.2 ABI', () => {
  const client = new ValidationRegistryClient({
    signerOrProvider: new ethers.JsonRpcProvider('http://127.0.0.1:1'),
    addressOrPreset: REGISTRY_PRESETS.sepolia
  });
  assert.equal(client.address, REGISTRY_PRESETS.sepolia.validationRegistry,
    'preset entry must resolve to the RI-deployed Validation Registry');
  const fn = client.contract.interface.getFunction('validationRequest');
  assert.ok(fn, 'validationRequest must exist');
  assert.deepEqual(
    fn.inputs.map((i) => i.name),
    ['validatorAddress', 'agentId', 'requestURI', 'requestHash'],
    'RI v1.2: requestHash is a mandatory caller input, validatorAddress comes first'
  );
  // requestHash is mandatory and must be a 32-byte hex — rejected before any chain call
  const bad = [1, '0xC26171A3c4e1d958cEA196A5e84B7418C58DCA2C', 'ipfs://kya', '0x1234'];
  const good = [1, '0xC26171A3c4e1d958cEA196A5e84B7418C58DCA2C', 'ipfs://kya', '0x' + 'aa'.repeat(32)];
  return client.requestValidation(...bad)
    .then(() => { throw new Error('must reject malformed requestHash'); })
    .catch((e) => { assert.ok(e instanceof TypeError); })
    .then(() => client.requestValidation(...good))
    .then(() => { throw new Error('offline provider must fail on send — reaching network means preflight passed'); })
    .catch((e) => { assert.ok(!(e instanceof TypeError), 'well-formed call may only fail on network'); });
});
