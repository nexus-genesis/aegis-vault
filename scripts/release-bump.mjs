#!/usr/bin/env node
/**
 * release-bump.mjs — coordinated version bump for the 6 published packages.
 *
 * WHY (external review 2026-08-24, P0 "发布断层"): the local CHANGELOG/README
 * describe on-chain Smart Account capabilities that npm users can't get because
 * the packages were never published at a matching version. And the package
 * versions are NOT all in sync (agent-keys is 0.5.0 while chain-eth/agent-mcp/
 * agent-sdk are 0.3.0), so publishing must bump in lockstep and re-point every
 * cross-package `^` range to the new versions — otherwise e.g. agent-sdk's
 * peerDependency `aegis-chain-eth: ^0.3.0` would never resolve to the new
 * chain-eth and on-chain capability would stay unreachable for SDK consumers.
 *
 * USAGE
 *   node scripts/release-bump.mjs            # dry-run: print what WOULD change
 *   node scripts/release-bump.mjs --apply    # write the changes in place
 *   node scripts/release-bump.mjs --to 0.4.0 # bump every package to exactly this
 *
 * DEFAULT (no --to): bump each package's MINOR one step, anchored so agent-keys
 * stays ahead (0.5.0 -> 0.6.0) while the rest go 0.3.x -> 0.4.x / 0.2.x -> 0.3.x.
 *
 * The script also rewrites any dependency/peerDependency cross references
 * (^0.3.0 etc.) inside every published package + the root package.json so the
 * workspace graph stays mutually consistent.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

// Published packages, keyed by repo-relative dir. Value = its package name.
const PUBLISHED = {
  'packages/agent-keys': null,
  'packages/agent-sdk': null,
  'packages/chain-eth': null,
  'packages/chain-sol': null,
  'packages/chain-adapters': null,
  'mcp-server': null,
};

// Every workspace package.json that must be scanned for cross-references.
const SCAN = [
  'package.json',
  ...Object.keys(PUBLISHED).map((p) => `${p}/package.json`),
];

const apply = process.argv.includes('--apply');
const toArgIdx = process.argv.indexOf('--to');
const to = toArgIdx !== -1 ? process.argv[toArgIdx + 1] : undefined;

function bumpMinor(v, forced) {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(v);
  if (!m) throw new Error(`Unparsable semver: ${v}`);
  const [, maj, min, patch] = m;
  const nextMin = forced !== undefined ? Number(forced.split('.')[1]) : Number(min) + 1;
  return `${maj}.${nextMin}.${patch}`;
}

function readName(dirName) {
  return JSON.parse(readFileSync(join(ROOT, dirName, 'package.json'), 'utf8')).name;
}
function readVersion(dirName) {
  return JSON.parse(readFileSync(join(ROOT, dirName, 'package.json'), 'utf8')).version;
}
function resolve(v) {
  return `^${v.split('.')[0]}.${v.split('.')[1]}.0`;
}

// 1. Load package names + compute new versions (never downgrade).
const nameByDir = {};
const newVersions = {};
for (const dir of Object.keys(PUBLISHED)) {
  nameByDir[dir] = readName(dir);
  const old = readVersion(dir);
  let next = bumpMinor(old, to);
  // Safety: never lower a version (e.g. --to 0.4.0 against agent-keys 0.5.0).
  if (to !== undefined && compareSemver(next, old) < 0) {
    console.error(`  SKIP downgrade guard: ${dir} ${old} -> ${next} blocked`);
    next = old;
  }
  newVersions[dir] = next;
}

// 2. For each scanned package.json, rewrite cross-references to the new versions.
let nRef = 0;
for (const abspath of SCAN) {
  const file = join(ROOT, abspath);
  if (!existsSync(file)) continue;
  const pkg = JSON.parse(readFileSync(file, 'utf8'));
  const before = JSON.stringify(pkg, null, 2);
  const ranges = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
  for (const dir of Object.keys(PUBLISHED)) {
    const name = nameByDir[dir];
    const newV = newVersions[dir];
    for (const field of ranges) {
      const dep = pkg[field];
      if (dep && dep[name] && /^\^/.test(dep[name]) && dep[name] !== resolve(newV)) {
        const oldRange = dep[name];
        dep[name] = resolve(newV);
        nRef++;
        console.log(`${apply ? '  [w]' : '  [~]'} ${abspath}: ${name} ${oldRange} -> ${dep[name]}`);
      }
    }
  }
  if (JSON.stringify(pkg, null, 2) !== before && apply) {
    writeFileSync(file, JSON.stringify(pkg, null, 2) + '\n');
  }
}

// 3. Write the bumped versions back (each package's own version field).
for (const dir of Object.keys(newVersions)) {
  const file = join(ROOT, dir, 'package.json');
  const pkg = JSON.parse(readFileSync(file, 'utf8'));
  const old = pkg.version;
  const next = newVersions[dir];
  pkg.version = next;
  console.log(`${apply ? '  [w]' : '  [~]'} ${dir}: ${old} -> ${next}`);
  if (apply) writeFileSync(file, JSON.stringify(pkg, null, 2) + '\n');
}

if (!apply) {
  console.log('\nDry-run only. Re-run with --apply to write. (tip: --apply --to 0.4.0 forces all to 0.4.0)');
}
console.log(`\nSummary: ${nRef} cross-reference(s), ${Object.keys(newVersions).length} package version(s).`);

function compareSemver(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}