import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  SUPPORTED_CHAINS,
  deriveChainAddresses,
  deriveChainAddress,
  deriveAgentFingerprint
} from '../src/registry.js';
import { generateKeyPair } from 'aegis-vault';

test('SUPPORTED_CHAINS lists nexus, eth, sol', () => {
  assert.deepEqual([...SUPPORTED_CHAINS].sort(), ['eth', 'nexus', 'sol']);
});

test('deriveChainAddresses produces valid addresses on all chains', async () => {
  const { publicKey, privateKey } = await generateKeyPair();
  const addrs = deriveChainAddresses(publicKey, privateKey);
  assert.match(addrs.nexus, /^ng1/);
  assert.match(addrs.eth, /^0x[0-9a-fA-F]{40}$/);
  assert.match(addrs.sol, /^[1-9A-HJ-NP-Za-km-z]+$/);
});

test('deriveChainAddress is stable and per-chain', async () => {
  const { publicKey, privateKey } = await generateKeyPair();
  const nexus = deriveChainAddress('nexus', publicKey, privateKey);
  const eth = deriveChainAddress('eth', publicKey, privateKey);
  const sol = deriveChainAddress('sol', publicKey, privateKey);
  assert.match(nexus, /^ng1/);
  assert.notEqual(nexus, eth);
  assert.notEqual(eth, sol);
  assert.throws(() => deriveChainAddress('btc', publicKey, privateKey), /Unsupported chain/);
});

test('deriveChainAddresses is deterministic for the same PQC key', async () => {
  const { publicKey, privateKey } = await generateKeyPair();
  const a = deriveChainAddresses(publicKey, privateKey);
  const b = deriveChainAddresses(publicKey, privateKey);
  assert.deepEqual(a, b);
});

test('deriveAgentFingerprint is a stable sha256', async () => {
  const { publicKey } = await generateKeyPair();
  const f1 = deriveAgentFingerprint(publicKey);
  const f2 = deriveAgentFingerprint(publicKey);
  assert.equal(f1, f2);
  assert.equal(f1.length, 64);
});