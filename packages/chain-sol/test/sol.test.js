import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  deriveSolPrivateKey,
  deriveSolWallet,
  deriveSolWalletFromPQC,
  addressFromPublicKey,
  publicKeyFromAddress,
  signMessage,
  verifyMessage
} from '../src/sol.js';
import { generateKeyPair } from 'aegis-vault';

test('deriveSolPrivateKey is deterministic per seed', () => {
  const a = deriveSolPrivateKey(Buffer.alloc(32, 0xab));
  const b = deriveSolPrivateKey(Buffer.alloc(32, 0xab));
  assert.equal(a.length, 32);
  assert.equal(a.toString('hex'), b.toString('hex'));
});

test('different seeds produce different SOL keys', () => {
  const a = deriveSolPrivateKey(Buffer.alloc(32, 0x01));
  const b = deriveSolPrivateKey(Buffer.alloc(32, 0x02));
  assert.notEqual(a.toString('hex'), b.toString('hex'));
});

test('deriveSolWallet produces a valid base58 address (44 chars typical)', () => {
  const w = deriveSolWallet(Buffer.alloc(32, 0x11));
  assert.equal(w.publicKeyHex.length, 64);
  assert.match(w.address, /^[1-9A-HJ-NP-Za-km-z]+$/); // base58 alphabet
  assert.ok(w.address.length >= 32 && w.address.length <= 44);
});

test('deriveSolWalletFromPQC derives a stable SOL wallet from a PQC key', async () => {
  const { privateKey } = await generateKeyPair();
  const w1 = deriveSolWalletFromPQC(privateKey);
  const w2 = deriveSolWalletFromPQC(privateKey);
  assert.equal(w1.address, w2.address);
  assert.equal(w1.publicKeyHex, w2.publicKeyHex);
});

test('publicKeyFromAddress round-trips', () => {
  const w = deriveSolWallet(Buffer.alloc(32, 0x33));
  const pub = publicKeyFromAddress(w.address);
  assert.equal(pub.toString('hex'), w.publicKeyHex);
});

test('signMessage / verifyMessage round-trips', () => {
  const w = deriveSolWallet(Buffer.alloc(32, 0x77));
  const sig = signMessage('hello agent', w.keypair.subarray(0, 32));
  assert.equal(sig.length, 64);
  assert.equal(verifyMessage('hello agent', sig, Buffer.from(w.publicKeyHex, 'hex')), true);
  assert.equal(verifyMessage('tampered', sig, Buffer.from(w.publicKeyHex, 'hex')), false);
});