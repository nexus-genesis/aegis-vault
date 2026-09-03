/**
 * aegis-chain-eth — canonical intent schema tests (Sprint 2)
 *
 * Pins the cross-language protocol shared with contracts/solidity/src/
 * SmartAccount.sol:
 *   - hashIntentDigest  ≡ SmartAccount._hashIntent  (keccak256 over the fixed
 *                         12-field preimage; every element is exactly 32 bytes)
 *   - signIntentDigest  ≡ plain secp256k1 (r||s||v) over the digest — low-S,
 *                         NO EIP-191 prefix, matching SmartAccount._recover
 *   - verifyIntentDigest≡ SmartAccount._recover + address comparison
 *
 * GOLDEN_* constants are the exact fixture baked into the Foundry suite
 * (contracts/solidity/test/SmartAccount.t.sol) so both sides pin the same
 * bytes — the cross-language golden vector.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  hashIntentDigest,
  signIntentDigest,
  verifyIntentDigest,
  addressForPrivateKey,
  signSmartAccountIntent,
  verifySmartAccountIntent,
} from '../src/canonical.js';
import { canonicalizeAssetIntent } from 'aegis-agent-sdk';

// ─── Golden fixture (fixed, non-random — mirrors SmartAccount.t.sol) ─────
const FIXED_PRIVKEY = '0x' + '11'.repeat(32);
const GOLDEN_ADDR = '0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A';
const GOLDEN_DIGEST = '0x11bba5575092be0c71c18c01324410a66db47ff580ace0edc433b2a29104d740';
const GOLDEN_SIG = '0x38715644a3619f2036d7b3db287f953b5b9e735663045f16bc34350f47633ea33a6e6d579aae7b9e711d78fca470cb71d8d93ae12f319f91d224b7bad65b9cfa1b';

function goldenCanonical() {
  return {
    type: 'agent_asset_intent',
    sessionId: '0x' + 'ab'.repeat(32),
    action: 'transfer',
    chain: 'ethereum',
    asset: 'USDC',
    amount: '100',
    recipient: '0xRecipient',
    contract: '0xContract',
    method: 'transfer',
    nonce: '1',
    agentId: 'agent-1',
    sessionIssuedAt: '1700000000000',
    sessionExpiresAt: '1700003600000',
  };
}

// ─── Digest (cross-language with Solidity _hashIntent) ───────────────────

test('hashIntentDigest matches the Solidity golden digest', () => {
  assert.equal(hashIntentDigest(goldenCanonical()), GOLDEN_DIGEST);
});

test('hashIntentDigest is independent of object key order (fixed schema)', () => {
  const a = goldenCanonical();
  const b = {
    sessionExpiresAt: a.sessionExpiresAt,
    sessionId: a.sessionId,
    method: a.method,
    amount: a.amount,
    contract: a.contract,
    nonce: a.nonce,
    action: a.action,
    sessionIssuedAt: a.sessionIssuedAt,
    recipient: a.recipient,
    agentId: a.agentId,
    asset: a.asset,
    chain: a.chain,
    type: a.type,
  };
  assert.equal(hashIntentDigest(b), hashIntentDigest(a));
});

test('hashIntentDigest is fail-closed on missing amount / nonce / sessionId', () => {
  const c = goldenCanonical();
  assert.throws(() => hashIntentDigest({ ...c, amount: undefined }), /amount/);
  assert.throws(() => hashIntentDigest({ ...c, nonce: undefined }), /nonce/);
  assert.throws(() => hashIntentDigest({ ...c, sessionId: undefined }), /sessionId/);
  assert.throws(() => hashIntentDigest({ ...c, sessionId: 'not-32-bytes' }), /sessionId/);
  assert.throws(() => hashIntentDigest(null), /canonical intent/);
  assert.throws(() => hashIntentDigest([]), /canonical intent/);
});

test('hashIntentDigest is fail-closed on missing/empty string fields (no collapsed preimages)', () => {
  const c = goldenCanonical();
  // undefined / null / '' must all be rejected, not silently coerced to the
  // hash of '' — otherwise two different intents collapse to one digest.
  for (const f of ['action', 'chain', 'asset', 'recipient', 'contract', 'method', 'agentId']) {
    assert.throws(() => hashIntentDigest({ ...c, [f]: undefined }), new RegExp(f));
    assert.throws(() => hashIntentDigest({ ...c, [f]: null }), new RegExp(f));
    assert.throws(() => hashIntentDigest({ ...c, [f]: ' ' }), new RegExp(f));
  }
  // timestamps are part of the signed digest and must be present
  assert.throws(() => hashIntentDigest({ ...c, sessionIssuedAt: undefined }), /sessionIssuedAt/);
  assert.throws(() => hashIntentDigest({ ...c, sessionExpiresAt: undefined }), /sessionExpiresAt/);
  // a fully-populated payload still hashes (no false positive)
  assert.equal(typeof hashIntentDigest(c), 'string');
});

// ─── Signature (cross-language with SmartAccount._recover) ───────────────

test('addressForPrivateKey derives the golden EVM address (cast-verified)', () => {
  assert.equal(addressForPrivateKey(FIXED_PRIVKEY).toLowerCase(), GOLDEN_ADDR.toLowerCase());
});

test('GOLDEN_SIG verifies against the golden digest + address (ecrecover mirror)', () => {
  assert.equal(verifyIntentDigest(GOLDEN_ADDR, GOLDEN_DIGEST, GOLDEN_SIG), true);
  // wrong address → false
  assert.equal(
    verifyIntentDigest('0x0000000000000000000000000000000000000001', GOLDEN_DIGEST, GOLDEN_SIG),
    false
  );
  // wrong digest → false
  assert.equal(verifyIntentDigest(GOLDEN_ADDR, '0x' + '00'.repeat(32), GOLDEN_SIG), false);
});

test('signIntentDigest round-trips through verifyIntentDigest', () => {
  const sig = signIntentDigest(GOLDEN_DIGEST, FIXED_PRIVKEY);
  assert.equal(verifyIntentDigest(GOLDEN_ADDR, GOLDEN_DIGEST, sig), true);
  assert.equal(verifyIntentDigest(GOLDEN_ADDR, '0x' + 'ff'.repeat(32), sig), false);
});

test('signIntentDigest is deterministic (RFC 6979) and low-S', () => {
  const sig1 = signIntentDigest(GOLDEN_DIGEST, FIXED_PRIVKEY);
  const sig2 = signIntentDigest(GOLDEN_DIGEST, FIXED_PRIVKEY);
  assert.equal(sig1, sig2);
  const s = BigInt('0x' + sig1.slice(66, 130));
  const LOW_S_MAX = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n;
  assert.ok(s <= LOW_S_MAX, 'signature must be low-S (EIP-2)');
});

test('verifyIntentDigest rejects a high-S (malleated) signature', () => {
  // Flip s → (n - s) keeps the signature valid but high-S; the contract and
  // the JS mirror must both reject it.
  const n = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
  const sig = Buffer.from(GOLDEN_SIG.replace(/^0x/, ''), 'hex');
  const s = BigInt('0x' + sig.subarray(32, 64).toString('hex'));
  const sFlip = n - s;
  const sHex = sFlip.toString(16).padStart(64, '0');
  const malleated = Buffer.concat([sig.subarray(0, 32), Buffer.from(sHex, 'hex'), sig.subarray(64, 65)]);
  assert.equal(verifyIntentDigest(GOLDEN_ADDR, GOLDEN_DIGEST, '0x' + malleated.toString('hex')), false);
});

test('verifyIntentDigest rejects malformed / zeroed / wrong-length signatures', () => {
  assert.equal(verifyIntentDigest(GOLDEN_ADDR, GOLDEN_DIGEST, '0x'), false);
  assert.equal(verifyIntentDigest(GOLDEN_ADDR, GOLDEN_DIGEST, '0x' + '00'.repeat(65)), false);
  assert.equal(verifyIntentDigest(GOLDEN_ADDR, GOLDEN_DIGEST, '0x' + 'ff'.repeat(64)), false);
  assert.equal(verifyIntentDigest(GOLDEN_ADDR, '0xdead', GOLDEN_SIG), false);
});

// ─── Integration: canonicalizeAssetIntent → digest → sign → verify ───────

test('canonicalizeAssetIntent output feeds the canonical digest + signature path', () => {
  const session = {
    agentId: 'agent-1',
    issuedAt: 1700000000000,
    expiresAt: 1700003600000,
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
  const canonical = canonicalizeAssetIntent(session, intent);
  // schema shape: fixed field set, 32-byte hex sessionId
  assert.equal(canonical.type, 'agent_asset_intent');
  assert.match(canonical.sessionId, /^0x[0-9a-f]{64}$/);
  assert.equal(canonical.agentId, 'agent-1');
  assert.equal(canonical.sessionIssuedAt, 1700000000000);
  assert.equal(canonical.sessionExpiresAt, 1700003600000);
  assert.equal(canonical.amount, '100');
  assert.equal(canonical.nonce, '1');

  // digest computes without throwing and sign/verify round-trips
  const digest = hashIntentDigest(canonical);
  const sig = signIntentDigest(digest, FIXED_PRIVKEY);
  assert.equal(verifyIntentDigest(GOLDEN_ADDR, digest, sig), true);

  // deriving again yields the SAME sessionId (deterministic from identity)
  const canonical2 = canonicalizeAssetIntent(session, intent);
  assert.equal(canonical2.sessionId, canonical.sessionId);
});

test('signSmartAccountIntent returns a Solidity-compatible payload + digest + signature', () => {
  const session = {
    agentId: 'agent-1',
    issuedAt: 1700000000000,
    expiresAt: 1700003600000,
    sessionId: '0x' + 'ab'.repeat(32),
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
  assert.equal(signed.payload.type, 'agent_asset_intent');
  assert.equal(signed.payload.sessionId, goldenCanonical().sessionId);
  assert.equal(signed.payload.action, goldenCanonical().action);
  assert.equal(signed.payload.chain, goldenCanonical().chain);
  assert.equal(signed.payload.asset, goldenCanonical().asset);
  assert.equal(signed.payload.amount, goldenCanonical().amount);
  assert.equal(signed.payload.recipient, goldenCanonical().recipient);
  assert.equal(signed.payload.contract, goldenCanonical().contract);
  assert.equal(signed.payload.method, goldenCanonical().method);
  assert.equal(signed.payload.nonce, goldenCanonical().nonce);
  assert.equal(signed.payload.agentId, goldenCanonical().agentId);
  assert.equal(String(signed.payload.sessionIssuedAt), goldenCanonical().sessionIssuedAt);
  assert.equal(String(signed.payload.sessionExpiresAt), goldenCanonical().sessionExpiresAt);
  assert.equal(signed.digest, GOLDEN_DIGEST);
  assert.equal(signed.signature, GOLDEN_SIG);
});

test('verifySmartAccountIntent round-trips the official EVM signing path', () => {
  const session = {
    agentId: 'agent-1',
    issuedAt: 1700000000000,
    expiresAt: 1700003600000,
    sessionId: '0x' + 'cd'.repeat(32),
  };
  const intent = {
    action: 'transfer',
    chain: 'ethereum',
    asset: 'USDC',
    amount: '5',
    recipient: '0xRecipient',
    contract: '0xContract',
    method: 'transfer',
    nonce: '9',
  };
  const signed = signSmartAccountIntent({ session, intent, privateKeyHex: FIXED_PRIVKEY });
  const ok = verifySmartAccountIntent({ address: GOLDEN_ADDR, signature: signed.signature, payload: signed.payload });
  assert.equal(ok.valid, true);
  assert.equal(ok.digest, signed.digest);
  const bad = verifySmartAccountIntent({
    address: '0x0000000000000000000000000000000000000001',
    signature: signed.signature,
    payload: signed.payload,
  });
  assert.equal(bad.valid, false);
});

test('explicit session.sessionId is honored (on-chain registration flow)', () => {
  const session = {
    agentId: 'agent-1',
    issuedAt: 1700000000000,
    expiresAt: 1700003600000,
    sessionId: '0x' + 'cd'.repeat(32),
  };
  const canonical = canonicalizeAssetIntent(session, {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '5',
    recipient: '0xRecipient', contract: '0xContract', method: 'transfer', nonce: '1',
  });
  assert.equal(canonical.sessionId, '0x' + 'cd'.repeat(32));
});
