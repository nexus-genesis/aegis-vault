/**
 * E1 hardening: V8 heap snapshot residue verification.
 *
 * Threat: after the transient plaintext reassembly inside ShardedSecret.use(),
 * JIT/GC timing might leave the contiguous secret somewhere on the V8 heap
 * even after secureZero() — surviving into any later heap snapshot export.
 *
 * Design: the secret is generated ONLY in this (parent) process. The child
 * (attack-simulations/heap-snapshot-sim.js) shards it, performs a transient
 * reassembly, destroys, GCs, and exports a FULL V8 heap snapshot. The parent
 * then scans the snapshot for both the binary secret and its ASCII hex form.
 * This cross-process separation guarantees the search needle itself can never
 * pollute the scanned heap.
 */
import test from 'node:test';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SIM = path.join(__dirname, 'attack-simulations', 'heap-snapshot-sim.js');

test('V8 heap snapshot contains no contiguous secret after use()+destroy()+GC', () => {
  const secret = crypto.randomBytes(32);
  const secretHex = secret.toString('hex');

  // Hand the hex to the child via a temp file (never argv/env of the child)
  const hexFile = path.join(os.tmpdir(), `ngx-hex-${crypto.randomUUID()}.txt`);
  fs.writeFileSync(hexFile, secretHex, { flag: 'w' });
  // Defensive: wipe the plaintext file content from this process' buffer cache
  // is unnecessary — parent heap is NOT scanned.

  let snapshotPath;
  try {
    const out = execFileSync(process.execPath, ['--expose-gc', SIM, hexFile], {
      encoding: 'utf-8',
      timeout: 60_000,
      maxBuffer: 16 * 1024 * 1024,
    });
    const lines = out.trim().split('\n');
    snapshotPath = lines[lines.length - 1];
    assert.ok(fs.existsSync(snapshotPath), `snapshot not found at ${snapshotPath}`);
  } finally {
    if (fs.existsSync(hexFile)) fs.unlinkSync(hexFile);
  }

  // Scan the full snapshot for both representations of the secret
  const snapshot = fs.readFileSync(snapshotPath);
  try {
    const binaryIndex = snapshot.indexOf(secret);
    assert.strictEqual(
      binaryIndex,
      -1,
      'FAIL: contiguous binary secret found in heap snapshot after GC'
    );

    const hexIndex = snapshot.indexOf(Buffer.from(secretHex, 'ascii'));
    assert.strictEqual(
      hexIndex,
      -1,
      'FAIL: ASCII hex of the secret found in heap snapshot after GC'
    );
  } finally {
    fs.unlinkSync(snapshotPath);
  }
}, { timeout: 120_000 });