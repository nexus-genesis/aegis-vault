/**
 * Aegis Vault agent-keys — Three-tier Authorization & Policy Time-lock tests
 *
 * Tests W2-3:
 *   1. resolveTier — amount-based tier resolution
 *   2. checkSpendAllowedTiered — gradient authorization with tier constraints
 *   3. PolicyTimelock — time-lock lifecycle (schedule, revoke, effective)
 *   4. Edge cases — inverted thresholds, negative amounts, zero amounts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  TIER_MODES,
  DEFAULT_TIER_THRESHOLDS,
  MEDIUM_TIER_TIMELOCK_MS,
  POLICY_TIMELOCK_MS,
  resolveTier,
  checkSpendAllowedTiered,
  PolicyTimelock,
  SPEND_MODES
} from '../src/index.js';

// ─── resolveTier ──────────────────────────────────────────────────────────

test('resolveTier.small_amount_returns_small_auto', () => {
  const tier = resolveTier('5', {
    smallThreshold: '10',
    largeThreshold: '100'
  });
  assert.equal(tier, TIER_MODES.SMALL_AUTO);
});

test('resolveTier.medium_amount_returns_medium_timelock', () => {
  const tier = resolveTier('50', {
    smallThreshold: '10',
    largeThreshold: '100'
  });
  assert.equal(tier, TIER_MODES.MEDIUM_TIMELOCK);
});

test('resolveTier.large_amount_returns_large_require_approval', () => {
  const tier = resolveTier('500', {
    smallThreshold: '10',
    largeThreshold: '100'
  });
  assert.equal(tier, TIER_MODES.LARGE_REQUIRE_APPROVAL);
});

test('resolveTier.exact_boundary_small_equals_smallThreshold_is_medium', () => {
  // Amount == smallThreshold (10) → not < 10, so it's medium.
  const tier = resolveTier('10', {
    smallThreshold: '10',
    largeThreshold: '100'
  });
  assert.equal(tier, TIER_MODES.MEDIUM_TIMELOCK);
});

test('resolveTier.exact_boundary_large_equals_largeThreshold_is_large', () => {
  // Amount == largeThreshold (100) → not < 100, so it's large.
  const tier = resolveTier('100', {
    smallThreshold: '10',
    largeThreshold: '100'
  });
  assert.equal(tier, TIER_MODES.LARGE_REQUIRE_APPROVAL);
});

test('resolveTier.zero_amount_returns_small_auto', () => {
  const tier = resolveTier('0', {
    smallThreshold: '10',
    largeThreshold: '100'
  });
  assert.equal(tier, TIER_MODES.SMALL_AUTO);
});

test('resolveTier.inverted_thresholds_defaults_to_large_require_approval', () => {
  // When small >= large, the system should fail-safe to require-approval.
  const tier = resolveTier('5', {
    smallThreshold: '100',
    largeThreshold: '10'  // inverted
  });
  assert.equal(tier, TIER_MODES.LARGE_REQUIRE_APPROVAL);
});

test('resolveTier.defaults_to_DEFAULT_TIER_THRESHOLDS', () => {
  const small = resolveTier('5');   // 5 < 10 → small
  assert.equal(small, TIER_MODES.SMALL_AUTO);

  const medium = resolveTier('50');  // 10 <= 50 < 100 → medium
  assert.equal(medium, TIER_MODES.MEDIUM_TIMELOCK);

  const large = resolveTier('500');  // 500 >= 100 → large
  assert.equal(large, TIER_MODES.LARGE_REQUIRE_APPROVAL);
});

// ─── checkSpendAllowedTiered ──────────────────────────────────────────────

test('checkSpendAllowedTiered.small_amount_auto_approved', () => {
  const config = { type: SPEND_MODES.UNLIMITED, tierThresholds: { smallThreshold: '10', largeThreshold: '100' } };
  const result = checkSpendAllowedTiered(config, { amount: '5' });
  assert.equal(result.allowed, true);
  assert.equal(result.tier, TIER_MODES.SMALL_AUTO);
});

test('checkSpendAllowedTiered.medium_amount_timelocked', () => {
  const config = { type: SPEND_MODES.UNLIMITED, tierThresholds: { smallThreshold: '10', largeThreshold: '100' } };
  const result = checkSpendAllowedTiered(config, { amount: '50' });
  assert.equal(result.allowed, true);
  assert.equal(result.tier, TIER_MODES.MEDIUM_TIMELOCK);
  assert.equal(result.timelockMs, MEDIUM_TIER_TIMELOCK_MS);
  assert.ok(result.scheduledAt > Date.now(), 'scheduledAt should be in the future');
  assert.equal(result.revocable, true);
});

test('checkSpendAllowedTiered.large_amount_requires_human_approval', () => {
  const config = { type: SPEND_MODES.UNLIMITED, tierThresholds: { smallThreshold: '10', largeThreshold: '100' } };
  const result = checkSpendAllowedTiered(config, { amount: '500' });
  assert.equal(result.allowed, false);
  assert.equal(result.tier, TIER_MODES.LARGE_REQUIRE_APPROVAL);
  assert.ok(result.reason.includes('human approval'));
  assert.equal(result.requiresApproval, true);
});

test('checkSpendAllowedTiered.respects_base_require_approval_mode', () => {
  // Even small amounts should be denied if the base mode is REQUIRE_APPROVAL.
  const config = { type: SPEND_MODES.REQUIRE_APPROVAL };
  const result = checkSpendAllowedTiered(config, { amount: '5' });
  assert.equal(result.allowed, false);
  assert.equal(result.tier, TIER_MODES.LARGE_REQUIRE_APPROVAL);
});

test('checkSpendAllowedTiered.respects_base_limit_mode', () => {
  const config = { type: SPEND_MODES.LIMITED, maxPerTx: '20', maxDaily: '100' };
  const result = checkSpendAllowedTiered(config, { amount: '25', spentToday: '0' });
  assert.equal(result.allowed, false);
  assert.ok(result.reason.includes('maxPerTx'));
});

test('checkSpendAllowedTiered.no_amount_fails_CLOSED', () => {
  // SECURITY: an authorization decision without knowing the amount must
  // never auto-approve (fail-open would make tiering trivially bypassable).
  const config = { type: SPEND_MODES.UNLIMITED };
  const result = checkSpendAllowedTiered(config, {});
  assert.equal(result.allowed, false);
  assert.equal(result.requiresApproval, true);
  assert.ok(result.reason.includes('fail-closed') || result.reason.includes('amount required'));
});

test('checkSpendAllowedTiered.negative_amount_rejected_by_base', () => {
  const config = { type: SPEND_MODES.UNLIMITED };
  const result = checkSpendAllowedTiered(config, { amount: '-5' });
  assert.equal(result.allowed, false);
  assert.ok(result.reason.includes('negative'));
});

test('checkSpendAllowedTiered.custom_tier_thresholds', () => {
  const config = {
    type: SPEND_MODES.UNLIMITED,
    tierThresholds: { smallThreshold: '100', largeThreshold: '1000' }
  };
  assert.equal(checkSpendAllowedTiered(config, { amount: '50' }).tier, TIER_MODES.SMALL_AUTO);
  assert.equal(checkSpendAllowedTiered(config, { amount: '500' }).tier, TIER_MODES.MEDIUM_TIMELOCK);
  assert.equal(checkSpendAllowedTiered(config, { amount: '5000' }).tier, TIER_MODES.LARGE_REQUIRE_APPROVAL);
});

// ─── PolicyTimelock ───────────────────────────────────────────────────────

test('PolicyTimelock.scheduleChange_creates_pending_change', () => {
  const timelock = new PolicyTimelock(1000); // 1s timelock for testing
  const result = timelock.scheduleChange('agent-01', { type: SPEND_MODES.REQUIRE_APPROVAL });

  assert.ok(result.changeId, 'must return a changeId');
  assert.ok(result.effectiveAt > Date.now(), 'effectiveAt must be in the future');
  assert.equal(timelock.pendingCount, 1);
});

test('PolicyTimelock.revokeChange_revokes_before_effective', () => {
  const timelock = new PolicyTimelock(60000); // 60s timelock
  const { changeId } = timelock.scheduleChange('agent-01', { type: SPEND_MODES.REQUIRE_APPROVAL });

  const result = timelock.revokeChange(changeId);
  assert.equal(result.revoked, true);
  assert.equal(timelock.pendingCount, 0);
});

test('PolicyTimelock.revokeChange_fails_for_unknown_changeId', () => {
  const timelock = new PolicyTimelock(60000);
  const result = timelock.revokeChange('nonexistent-id');
  assert.equal(result.revoked, false);
  assert.ok(result.reason.includes('not found'));
});

test('PolicyTimelock.revokeChange_fails_for_effective_change', () => {
  const timelock = new PolicyTimelock(1); // 1ms timelock
  const { changeId } = timelock.scheduleChange('agent-01', { type: SPEND_MODES.UNLIMITED });

  // Wait for the timelock to expire.
  return new Promise(resolve => {
    setTimeout(() => {
      const result = timelock.revokeChange(changeId);
      assert.equal(result.revoked, false);
      assert.ok(result.reason.includes('already effective'));
      resolve();
    }, 50);
  });
});

test('PolicyTimelock.getEffectiveChanges_returns_after_timelock', () => {
  const timelock = new PolicyTimelock(10); // 10ms timelock
  timelock.scheduleChange('agent-01', { type: SPEND_MODES.UNLIMITED });

  // Initially, no effective changes.
  assert.equal(timelock.getEffectiveChanges().length, 0);

  // Wait for timelock to expire.
  return new Promise(resolve => {
    setTimeout(() => {
      const changes = timelock.getEffectiveChanges();
      assert.equal(changes.length, 1);
      assert.equal(changes[0].agentId, 'agent-01');
      assert.equal(changes[0].newPolicy.type, SPEND_MODES.UNLIMITED);
      assert.equal(timelock.pendingCount, 0);
      resolve();
    }, 50);
  });
});

test('PolicyTimelock.getChange_returns_pending_change_details', () => {
  const timelock = new PolicyTimelock(60000);
  const { changeId } = timelock.scheduleChange('agent-01', { type: SPEND_MODES.UNLIMITED });

  const change = timelock.getChange(changeId);
  assert.ok(change, 'should return change details');
  assert.equal(change.agentId, 'agent-01');
  assert.equal(change.newPolicy.type, SPEND_MODES.UNLIMITED);
  assert.ok(change.remainingMs > 0, 'remainingMs should be positive');
});

test('PolicyTimelock.getChange_returns_null_for_unknown', () => {
  const timelock = new PolicyTimelock(60000);
  assert.equal(timelock.getChange('unknown'), null);
});

test('PolicyTimelock.clearAll_removes_all_pending', () => {
  const timelock = new PolicyTimelock(60000);
  timelock.scheduleChange('agent-01', { type: SPEND_MODES.UNLIMITED });
  timelock.scheduleChange('agent-02', { type: SPEND_MODES.REQUIRE_APPROVAL });

  assert.equal(timelock.pendingCount, 2);
  const cleared = timelock.clearAll();
  assert.equal(cleared, 2);
  assert.equal(timelock.pendingCount, 0);
});

test('PolicyTimelock.constructor_rejects_invalid_timeout', () => {
  assert.throws(() => new PolicyTimelock('not-a-number'), /non-negative/);
  assert.throws(() => new PolicyTimelock(-1), /non-negative/);
});

test('PolicyTimelock.scheduleChange_rejects_invalid_args', () => {
  const timelock = new PolicyTimelock(60000);
  assert.throws(() => timelock.scheduleChange('', { type: SPEND_MODES.UNLIMITED }), /agentId/);
  assert.throws(() => timelock.scheduleChange('agent-01', null), /newPolicy/);
});

// ─── Integration: checkSpendAllowedTiered + PolicyTimelock ────────────────

test('medium_tier_creates_revocable_timelock_entry', () => {
  const config = { type: SPEND_MODES.UNLIMITED, tierThresholds: { smallThreshold: '10', largeThreshold: '100' } };
  const result = checkSpendAllowedTiered(config, { amount: '50' });

  assert.equal(result.allowed, true);
  assert.equal(result.revocable, true);
  assert.ok(result.scheduledAt > Date.now());

  // Simulate a human revoking this timelock authorization.
  // Use a timelock long enough to allow revocation before effectiveness.
  const timelock = new PolicyTimelock(60000); // 60s timelock
  const { changeId } = timelock.scheduleChange('agent-01', { type: SPEND_MODES.REQUIRE_APPROVAL });
  const revoke = timelock.revokeChange(changeId);
  assert.equal(revoke.revoked, true);
});

test('tiered_flow_auto_small_deny_large', () => {
  const config = { type: SPEND_MODES.UNLIMITED, tierThresholds: { smallThreshold: '10', largeThreshold: '100' } };

  // Small: auto-approved
  assert.equal(checkSpendAllowedTiered(config, { amount: '5' }).allowed, true);

  // Medium: timelocked but allowed
  assert.equal(checkSpendAllowedTiered(config, { amount: '50' }).allowed, true);

  // Large: denied
  assert.equal(checkSpendAllowedTiered(config, { amount: '500' }).allowed, false);
});