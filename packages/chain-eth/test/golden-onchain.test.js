/**
 * aegis-chain-eth — golden vectors RE-RUN ON-CHAIN (Sprint 2.3 T4)
 *
 * PURPOSE
 * ───────
 * The cross-language golden fixture lives in TWO offline places:
 *   - JS:  packages/chain-eth/test/canonical.test.js (GOLDEN_DIGEST/SIG/ADDR)
 *   - Sol: contracts/solidity/test/SmartAccount.t.sol (same constants baked
 *          in, asserted via vm)
 *
 * T4 closes the loop by RE-RUNNING the same fixed golden fixture against a
 * REAL EVM chain through ethers.js — a third, independent executor of the
 * protocol. If all three agree, the JS digest/signature code, the Solidity
 * hashIntent/_recover, and the actual broadcast path are mutually consistent:
 *
 *   1. Deploy SmartAccount, register the EXACT golden session from the
 *      Foundry fixture (agentEvmAddress = GOLDEN_ADDR, fixed issued/expires).
 *   2. Read on-chain hashIntent(golden intent) → MUST equal GOLDEN_DIGEST.
 *   3. Broadcast the FIXED GOLDEN_SIG via executeFromAgent → the contract's
 *      ecrecover must recover GOLDEN_ADDR and every policy check must pass
 *      (this is precisely the Foundry test_golden_signature_executes, run on
 *      a live chain).
 *   4. Tamper with `amount` (the same INV-002 vector the Foundry suite pins)
 *      → chain must reject with InvalidSignature.
 *
 * TIME CONTROL: the golden session window is Nov 2023
 * (ISSUED_AT=1700000000000 / EXPIRES_AT=1700003600000 ms). LocalChain's clock
 * defaults to now (2026), which would make the session expired on-chain
 * (INV-003 SessionExpired). We therefore boot LocalChain with
 * `initialTimeMs` inside the golden window so executeFromAgent sees a live
 * session — mirroring Foundry's warp-to-window behavior.
 *
 * Skips (with a hint) when the compiled artifact is absent: it needs a local
 * `forge build --use 0.8.24` in contracts/solidity, or
 * SMART_ACCOUNT_ARTIFACT pointing at the built artifact JSON.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ethers } from 'ethers';

import { createLocalChain } from './helpers/local-chain.mjs';
import { loadSmartAccountArtifact, artifactMissingHint } from './helpers/load-artifact.mjs';
import { deploySmartAccount, createChainProvider } from '../src/chain-connection.js';
import {
  signSmartAccountIntent,
  addressForPrivateKey,
  hashIntentDigest,
} from '../src/canonical.js';

const artifact = loadSmartAccountArtifact();
const skipOnChain = artifact ? false : artifactMissingHint();

// BigInt-safe JSON for assertion diagnostics (revert args are bigint).
const diag = (value) => JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));

// ─── Golden fixture (fixed — mirrors canonical.test.js / SmartAccount.t.sol) ─
const FIXED_PRIVKEY = '0x' + '11'.repeat(32);
const GOLDEN_ADDR = '0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A';
const GOLDEN_DIGEST = '0x11bba5575092be0c71c18c01324410a66db47ff580ace0edc433b2a29104d740';
const GOLDEN_SIG = '0x38715644a3619f2036d7b3db287f953b5b9e735663045f16bc34350f47633ea33a6e6d579aae7b9e711d78fca470cb71d8d93ae12f319f91d224b7bad65b9cfa1b';

const SESSION_ID = '0x' + 'ab'.repeat(32);
const ISSUED_AT = 1700000000000; // ms epoch — matches the golden fixture
const EXPIRES_AT = 1700003600000;
// Chain clock sits inside the golden session window (Nov 2023).
const GOLDEN_TIME_MS = 1700001800000;

// Broadcast/owner/emergency EOAs (fresh, deterministic, funded by LocalChain).
const OWNER_PK = '0x' + '21'.repeat(32);
const EMERGENCY_PK = '0x' + '22'.repeat(32);
const RELAYER_PK = '0x' + '33'.repeat(32);

const owner = new ethers.Wallet(OWNER_PK);
const emergency = new ethers.Wallet(EMERGENCY_PK);
const relayer = new ethers.Wallet(RELAYER_PK);

/** The exact golden intent — 12 fields, byte-for-byte the Foundry _intent(100,1). */
function goldenIntent() {
  return {
    sessionId: SESSION_ID,
    action: 'transfer',
    chain: 'ethereum',
    asset: 'USDC',
    amount: '100',
    recipient: '0xRecipient',
    contract: '0xContract',
    method: 'transfer',
    nonce: '1',
    agentId: 'agent-1',
    sessionIssuedAt: String(ISSUED_AT),
    sessionExpiresAt: String(EXPIRES_AT),
  };
}

/** Whitelist matching the Foundry _registerGoldenSession call exactly. */
const GOLDEN_WHITELIST = {
  allowedChains: ['ethereum'],
  allowedAssets: ['USDC'],
  allowedContracts: ['0xContract'],
  allowedMethods: ['transfer'],
  allowedRecipients: ['0xRecipient'],
};

/** Boot a LocalChain (golden-window clock) + deploy SmartAccount. */
async function deployChain({ fundRelayer = false } = {}) {
  const funded = [
    { address: owner.address, balance: 10n ** 18n },
    { address: emergency.address, balance: 10n ** 18n },
  ];
  if (fundRelayer) funded.push({ address: relayer.address, balance: 10n ** 18n });
  const chain = await createLocalChain({ initialTimeMs: GOLDEN_TIME_MS, funded });
  const provider = createChainProvider(chain.url);
  const dep = await deploySmartAccount({
    provider,
    signer: owner.connect(provider),
    abi: artifact.abi,
    bytecode: artifact.bytecode.object,
    owner: owner.address,
    emergencyKey: emergency.address,
    accountMaxDaily: 1_000_000,
  });
  assert.equal(dep.ok, true, diag(dep));
  return { chain, provider, conn: dep.connection };
}

/** Deploy + register the EXACT golden session from the Foundry fixture. */
async function setupChain({ fundRelayer = true } = {}) {
  const { chain, provider, conn } = await deployChain({ fundRelayer });
  const reg = await conn.registerSession({
    sessionId: SESSION_ID,
    agentId: 'agent-1',
    agentEvmAddress: GOLDEN_ADDR,
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    maxPerTx: 1000,
    maxDaily: 5000,
    whitelist: GOLDEN_WHITELIST,
  });
  assert.equal(reg.ok, true, diag(reg));
  return { chain, provider, conn };
}

// ─── Golden vectors on a real chain ───────────────────────────────────────

test(
  'on-chain golden digest == GOLDEN_DIGEST (hashIntent vs JS canonical)',
  { skip: skipOnChain },
  async () => {
    const { chain, conn } = await deployChain({ fundRelayer: false });
    try {
      // Cross-language digest: contract.hashIntent(golden intent) must equal
      // the JS hashIntentDigest over the same fields.
      const onChainDigest = await conn.hashIntent(goldenIntent());
      assert.equal(onChainDigest, GOLDEN_DIGEST);
      assert.equal(hashIntentDigest(goldenIntent()), GOLDEN_DIGEST);
    } finally {
      await chain.stop();
    }
  },
);

test(
  'golden vectors broadcast on-chain: register golden session → execute GOLDEN_SIG',
  { skip: skipOnChain },
  async () => {
    const { chain, provider, conn } = await setupChain({ fundRelayer: true });
    try {
      // Broadcast the FIXED GOLDEN_SIG. The contract ecrecover must yield
      // GOLDEN_ADDR and every policy check must pass — the Foundry
      // test_golden_signature_executes, executed on a live chain.
      const exec = await conn.executeFromAgent({
        payload: goldenIntent(),
        signature: GOLDEN_SIG,
        signer: relayer.connect(provider), // any EOA may relay
      });
      assert.equal(exec.ok, true, diag(exec));
      assert.equal(exec.amount, 100n, 'Executed event amount == 100 (INV-002)');
      assert.equal(exec.txId?.length, 66, 'Executed event txId is bytes32');
      assert.equal(exec.sessionId, SESSION_ID);

      // On-chain state after the golden execution.
      assert.equal(await conn.sessionLastNonce(SESSION_ID), 1n, 'sessionLastNonce == 1');
      assert.equal(await conn.sessionSpentThisWindow(SESSION_ID), 100n, 'sessionSpentThisWindow == 100');

      // Replaying the SAME golden signature (nonce=1 already used) is
      // rejected on-chain → BadNonce (INV-007 anti-replay).
      const replay = await conn.simulateExecuteFromAgent({
        payload: goldenIntent(),
        signature: GOLDEN_SIG,
      });
      assert.equal(replay.ok, false, diag(replay));
      assert.equal(replay.errorName, 'BadNonce', diag(replay));
    } finally {
      await chain.stop();
    }
  },
);

test(
  'INV-002 on-chain: amount tampering breaks GOLDEN_SIG recovery → InvalidSignature',
  { skip: skipOnChain },
  async () => {
    const { chain, conn } = await setupChain({ fundRelayer: false });
    try {
      // GOLDEN_SIG is bound to amount=100; amount=101 changes the digest, so
      // ecrecover no longer yields GOLDEN_ADDR → InvalidSignature (INV-002).
      const tampered = { ...goldenIntent(), amount: '101' };
      const res = await conn.simulateExecuteFromAgent({ payload: tampered, signature: GOLDEN_SIG });
      assert.equal(res.ok, false, diag(res));
      assert.equal(res.errorName, 'InvalidSignature', diag(res));
    } finally {
      await chain.stop();
    }
  },
);

// ─── JS reproduction of the golden fixture (no chain) ─────────────────────

test('signSmartAccountIntent reproduces the exact golden fixture bytes', () => {
  const session = {
    sessionId: SESSION_ID,
    agentId: 'agent-1',
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
  };
  const intent = {
    action: 'transfer',
    chain: 'ethereum',
    asset: 'USDC',
    amount: '100',
    recipient: '0xRecipient',
    contract: '0xContract',
    method: 'transfer',
    nonce: '1',
  };
  const signed = signSmartAccountIntent({ session, intent, privateKeyHex: FIXED_PRIVKEY });
  assert.equal(signed.digest, GOLDEN_DIGEST);
  assert.equal(signed.signature, GOLDEN_SIG);
  assert.equal(addressForPrivateKey(FIXED_PRIVKEY), GOLDEN_ADDR);
});
