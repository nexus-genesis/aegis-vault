/**
 * E4 hardening: PolicyTimelock alerting (detect → delay → respond loop).
 */
import test from 'node:test';
import assert from 'node:assert';
import { createServer } from 'node:http';
import { PolicyTimelock } from '../src/takeover.js';

test('addNotifier fires on schedule / revoke / effective / clearAll', () => {
  const events = [];
  const tl = new PolicyTimelock(50).addNotifier(e => events.push(e));

  const { changeId } = tl.scheduleChange('agent-1', { type: 'limit', maxPerTx: '5' });
  tl.revokeChange(changeId);
  assert.deepStrictEqual(events.map(e => e.event), [
    'policy_change_scheduled',
    'policy_change_revoked',
  ]);

  // scheduled → effective
  const second = tl.scheduleChange('agent-2', { type: 'unlimited' });
  events.length = 0;
  return new Promise(resolve => setTimeout(resolve, 80)).then(() => {
    tl.getEffectiveChanges();
    assert.strictEqual(events.map(e => e.event)[0], 'policy_change_effective');
    assert.strictEqual(events[0].agentId, 'agent-2');
    assert.deepStrictEqual(events[0].newPolicy, { type: 'unlimited' });

    // clearAll only emits when something was actually pending
    events.length = 0;
    tl.scheduleChange('agent-3', { type: 'limit' });
    tl.clearAll();
    assert.deepStrictEqual(events.map(e => e.event), [
      'policy_change_scheduled',
      'policy_changes_cleared',
    ]);
  });
});

test('notifier exceptions never break the enforcement path', () => {
  const tl = new PolicyTimelock(1000).addNotifier(() => { throw new Error('boom'); });
  const { changeId } = tl.scheduleChange('agent-x', { type: 'limit' }); // must not throw
  assert.strictEqual(tl.revokeChange(changeId).revoked, true);
});

test('scheduled event carries full context for human triage', () => {
  const seen = [];
  const tl = new PolicyTimelock(1234).addNotifier(e => seen.push(e));
  const { changeId, effectiveAt } = tl.scheduleChange('agent-alert', { type: 'unlimited' });
  const e = seen[0];
  assert.strictEqual(e.event, 'policy_change_scheduled');
  assert.strictEqual(e.agentId, 'agent-alert');
  assert.strictEqual(e.changeId, changeId);
  assert.strictEqual(e.effectiveAt, effectiveAt);
  assert.strictEqual(e.timelockMs, 1234);
  assert.deepStrictEqual(e.newPolicy, { type: 'unlimited' });
});

test('webhook URL receives POSTed JSON event', async () => {
  const received = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      received.push({ method: req.method, body: JSON.parse(body) });
      res.writeHead(204);
      res.end();
    });
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  const tl = new PolicyTimelock(1000, { webhookUrl: `http://127.0.0.1:${port}/hook` });
  tl.scheduleChange('agent-webhook', { type: 'unlimited' });

  // fire-and-forget delivery — poll briefly
  const deadline = Date.now() + 3000;
  while (received.length === 0 && Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 25));
  }
  server.close();

  assert.strictEqual(received.length, 1);
  assert.strictEqual(received[0].method, 'POST');
  assert.strictEqual(received[0].body.event, 'policy_change_scheduled');
  assert.strictEqual(received[0].body.source, 'aegis-vault');
  assert.strictEqual(received[0].body.agentId, 'agent-webhook');
});

test('webhook failures are logged, not thrown', async () => {
  // port 1 on 127.0.0.1 — connection refused territory
  const tl = new PolicyTimelock(1000, { webhookUrl: 'http://127.0.0.1:1/nope' });
  assert.doesNotThrow(() => tl.scheduleChange('agent-fail', { type: 'limit' }));
  // give the rejected fetch a moment to settle
  await new Promise(r => setTimeout(r, 100));
});

test('addNotifier validates input', () => {
  const tl = new PolicyTimelock();
  assert.throws(() => tl.addNotifier('not-a-function'), TypeError);
});