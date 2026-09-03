/**
 * deny-list-sync.test.js — enforces the Sprint 2 single-source-of-truth rule
 * (Q1): the on-chain deny list must be generated from the JS canonical sets,
 * so JS and Solidity can never drift on which actions are rejected.
 *
 * Contract:
 *   contracts/solidity/testdata/deny-actions.json  (generated fixture)
 *   contracts/solidity/src/DenyList.sol            (generated Solidity library)
 *   both derived by scripts/sync-deny-list.mjs from SELF_ESCALATION_ACTIONS /
 *   ALLOWANCE_SURFACE_ACTIONS in packages/chain-eth/src/smart-account.js
 *
 * Run `node scripts/sync-deny-list.mjs` after editing the JS sets and commit
 * the regenerated files together.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  ALLOWANCE_SURFACE_ACTIONS,
  SELF_ESCALATION_ACTIONS,
  normalizeAction,
} from '../src/smart-account.js';

const here = dirname(fileURLToPath(import.meta.url));
const denyJson = JSON.parse(
  readFileSync(join(here, '../../../contracts/solidity/testdata/deny-actions.json'), 'utf8'),
);
const denyListSol = readFileSync(join(here, '../../../contracts/solidity/src/DenyList.sol'), 'utf8');

const sorted = (arr) => [...new Set(arr)].sort();
const normalized = (set) => sorted([...set].map((s) => normalizeAction(s)));

test('deny-actions.json mirrors SELF_ESCALATION_ACTIONS (normalized)', () => {
  assert.deepEqual(sorted(denyJson.self_escalation), normalized(SELF_ESCALATION_ACTIONS));
});

test('deny-actions.json mirrors ALLOWANCE_SURFACE_ACTIONS (normalized)', () => {
  assert.deepEqual(sorted(denyJson.allowance_surface), normalized(ALLOWANCE_SURFACE_ACTIONS));
});

test('every deny-actions.json entry is already canonical (normalized form)', () => {
  for (const e of [...denyJson.self_escalation, ...denyJson.allowance_surface]) {
    assert.equal(normalizeAction(e), e, `entry should already be normalized: ${e}`);
    assert.match(e, /^[a-z0-9]+$/, `entry must be a lowercase ASCII word: ${e}`);
  }
});

test('DenyList.sol is generated from deny-actions.json (every entry present)', () => {
  for (const e of [...denyJson.self_escalation, ...denyJson.allowance_surface]) {
    assert.ok(denyListSol.includes(`keccak256("${e}")`), `missing DenyList.sol literal for "${e}"`);
  }
  // normalizer must be case/separator-insensitive like the JS normalizeAction
  assert.match(denyListSol, /function normalize\(/);
  assert.match(denyListSol, /0x5f/);   // underscore stripped
  assert.match(denyListSol, /0x2d/);   // dash stripped
  assert.match(denyListSol, /0x41 && c <= 0x5a/); // A-Z lowercased
});
