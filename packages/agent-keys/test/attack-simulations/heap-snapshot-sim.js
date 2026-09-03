#!/usr/bin/env node
/**
 * aegis-vault — V8 heap snapshot simulation (E1 hardening)
 *
 * Child process in the heap-snapshot test. It receives the ASCII hex form of
 * a secret via a temp FILE (never argv/env/stdin-string, so no hex string is
 * ever materialized in this process), shards it, forces a transient
 * reassembly (the exact operation that would leave residue if memory hygiene
 * failed), destroys the shards, triggers GC, then writes a full V8 heap
 * snapshot to disk for the parent to scan.
 *
 * Run with: node --expose-gc heap-snapshot-sim.js <path-to-hex-file>
 * Prints the snapshot path on stdout as the last line.
 */

import { ShardedSecret } from '../../src/secure.js';
import v8 from 'node:v8';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const hexPath = process.argv[2];
if (!hexPath) {
  console.error('usage: heap-snapshot-sim.js <hex-file>');
  process.exit(2);
}

// Decode ASCII hex → Buffer WITHOUT ever creating a JS string of the secret.
// (A string would itself be a heap-resident copy of the plaintext.)
function hexVal(byte) {
  if (byte >= 0x30 && byte <= 0x39) return byte - 0x30;       // 0-9
  if (byte >= 0x61 && byte <= 0x66) return byte - 0x61 + 10;  // a-f
  if (byte >= 0x41 && byte <= 0x46) return byte - 0x41 + 10;  // A-F
  throw new Error('non-hex byte in input');
}

const hexBuf = fs.readFileSync(hexPath);
fs.unlinkSync(hexPath); // remove the file copy immediately

const len = Math.floor(hexBuf.length / 2);
const secret = Buffer.alloc(len);
for (let i = 0; i < len; i++) {
  secret[i] = (hexVal(hexBuf[2 * i]) << 4) | hexVal(hexBuf[2 * i + 1]);
}
hexBuf.fill(0); // zero the ASCII form

// 1. Shard (constructor zeroes the caller's copy per Wave 1 contract)
const sharded = new ShardedSecret(secret);

// 2. Force the transient plaintext reassembly — the residue-producing op
sharded.use(pk => pk.length);

// 3. Destroy shards
sharded.destroy();

// 4. Full GC sweep (requires --expose-gc)
if (typeof global.gc !== 'function') {
  console.error('FATAL: run with --expose-gc');
  process.exit(3);
}
for (let i = 0; i < 5; i++) global.gc();

// 5. Dump the entire heap (writeHeapSnapshot expects a FILE path)
const snapshotPath = path.join(
  os.tmpdir(),
  `ngx-heap-${process.pid}-${Date.now()}.heapsnapshot`
);
v8.writeHeapSnapshot(snapshotPath);
console.log(snapshotPath);