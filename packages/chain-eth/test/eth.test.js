import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  deriveEthPrivateKey,
  deriveEthWallet,
  deriveEthWalletFromPQC,
  addressFromPrivateKey,
  toChecksumAddress,
  signMessage,
  verifyMessage,
  mapSpendToGuardianPolicy,
  isValidSeed
} from '../src/eth.js';
import { generateKeyPair } from 'aegis-vault';

test('deriveEthPrivateKey is deterministic per seed', () => {
  const seed = Buffer.alloc(32, 0xab);
  const a = deriveEthPrivateKey(seed);
  const b = deriveEthPrivateKey(seed);
  assert.equal(a.toString('hex'), b.toString('hex'));
  assert.equal(a.length, 32);
});

test('different seeds produce different ETH keys', () => {
  const a = deriveEthPrivateKey(Buffer.alloc(32, 0x01));
  const b = deriveEthPrivateKey(Buffer.alloc(32, 0x02));
  assert.notEqual(a.toString('hex'), b.toString('hex'));
});

test('isValidSeed validates length', () => {
  assert.equal(isValidSeed(Buffer.alloc(32)), true);
  assert.equal(isValidSeed(Buffer.alloc(31)), false);
  assert.equal(isValidSeed(null), false);
});

test('addressFromPrivateKey produces a valid 42-char checksummed address', () => {
  const wallet = deriveEthWallet(Buffer.alloc(32, 0x11));
  assert.match(wallet.address, /^0x[0-9a-fA-F]{40}$/);
  assert.equal(wallet.privateKeyHex.length, 64);
  // Address derived from public key must match the one from the private key.
  assert.equal(addressFromPrivateKey(Buffer.from(wallet.privateKeyHex, 'hex')), wallet.address);
});

test('deriveEthWalletFromPQC derives a stable ETH wallet from a PQC key', async () => {
  const { privateKey } = await generateKeyPair();
  const w1 = deriveEthWalletFromPQC(privateKey);
  const w2 = deriveEthWalletFromPQC(privateKey);
  assert.equal(w1.address, w2.address);
  assert.equal(w1.privateKeyHex, w2.privateKeyHex);
  assert.match(w1.address, /^0x[0-9a-fA-F]{40}$/);
});

test('toChecksumAddress is EIP-55 valid', () => {
  // EIP-55 example: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
  const checksummed = toChecksumAddress('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed');
  assert.equal(checksummed, '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed');
});

test('signMessage / verifyMessage round-trips (recoverable EIP-191)', () => {
  const wallet = deriveEthWallet(Buffer.alloc(32, 0x77));
  const sig = signMessage('hello agent', wallet.privateKeyHex);
  assert.equal(sig.length, 65);
  assert.equal(verifyMessage(wallet.address, 'hello agent', sig), true);
  assert.equal(verifyMessage(wallet.address, 'tampered', sig), false);
});

test('signature verifies against a different wallet address returns false', () => {
  const w1 = deriveEthWallet(Buffer.alloc(32, 0x01));
  const w2 = deriveEthWallet(Buffer.alloc(32, 0x02));
  const sig = signMessage('data', w1.privateKeyHex);
  assert.equal(verifyMessage(w2.address, 'data', sig), false);
});

test('mapSpendToGuardianPolicy maps spend modes to EVM policies', () => {
  assert.deepEqual(mapSpendToGuardianPolicy({ type: 'unlimited' }), { policy: 'unlimited' });
  assert.deepEqual(
    mapSpendToGuardianPolicy({ type: 'limit', maxPerTx: 100n, maxDaily: 500n }),
    { policy: 'limit', maxPerTx: '100', maxDaily: '500' }
  );
  assert.deepEqual(mapSpendToGuardianPolicy({ type: 'require-approval' }), {
    policy: 'require-approval', maxPerTx: '0', maxDaily: '0'
  });
  assert.deepEqual(mapSpendToGuardianPolicy(undefined), { policy: 'unlimited' });
});