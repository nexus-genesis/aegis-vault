import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer } from '../src/server.js';

let server;
let client;
let clientTransport;
let serverTransport;

before(async () => {
  server = createServer();
  [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  client = new Client({ name: 'test-client', version: '1.0.0' }, { capabilities: {} });
  await client.connect(clientTransport);
});

after(async () => {
  await client.close();
  await server.close();
});

async function callTool(name, args) {
  const res = await client.callTool({ name, arguments: args });
  return JSON.parse(res.content[0].text);
}

test('lists security tools', async () => {
  const tools = await client.listTools();
  const names = tools.tools.map((t) => t.name);
  for (const expected of ['generate_agent_keys', 'generate_keypair', 'verify_signature', 'validate_address', 'check_spend', 'takeover_guard']) {
    assert.ok(names.includes(expected), `missing tool ${expected}`);
  }
});

test('lists task economy + forum tools (AGENT world bridge)', async () => {
  const tools = await client.listTools();
  const names = tools.tools.map((t) => t.name);
  for (const expected of [
    'register_agent', 'get_status', 'get_agents', 'get_agent', 'get_leaderboard',
    'list_tasks', 'get_task', 'claim_task', 'submit_task', 'verify_task', 'publish_task',
    'list_topics', 'create_topic', 'add_post', 'vote',
  ]) {
    assert.ok(names.includes(expected), `missing tool ${expected}`);
  }
});

test('generate_agent_keys returns a self-sovereign identity (no private key leaked)', async () => {
  const out = await callTool('generate_agent_keys', { password: 'agent-secret-123', metadata: { name: 'alice' } });
  assert.equal(out.success, true);
  assert.equal(out.keyModel, 'self-sovereign');
  assert.match(out.address, /^ng1/);
  assert.equal(out.publicKeyHex.length, 2624); // 1312 bytes hex
  assert.ok(out.envelope && out.envelope.ciphertext, 'envelope must contain encrypted private key');
  assert.equal('privateKeyHex' in out, false, 'raw private key must never be emitted');
});

test('verify_signature validates a PQC signature', async () => {
  const { sign, verify } = await import('aegis-vault');
  const { publicKey, privateKey } = await import('aegis-vault').then((m) => m.generateKeyPair());
  const message = 'hello agent';
  const sig = await sign(message, privateKey);
  const ok = await callTool('verify_signature', {
    message,
    signature: sig.toString('hex'),
    publicKeyHex: publicKey.toString('hex'),
  });
  assert.equal(ok.valid, true);

  const bad = await callTool('verify_signature', {
    message: 'tampered',
    signature: sig.toString('hex'),
    publicKeyHex: publicKey.toString('hex'),
  });
  assert.equal(bad.valid, false);
});

test('validate_address accepts valid ng1 and rejects garbage', async () => {
  const { generateAddress } = await import('aegis-vault');
  const keypair = await import('aegis-vault').then((m) => m.generateKeyPair());
  const addr = generateAddress(keypair.publicKey);
  assert.equal((await callTool('validate_address', { address: addr })).valid, true);
  assert.equal((await callTool('validate_address', { address: 'not-an-address' })).valid, false);
});

test('check_spend enforces human-set ceilings', async () => {
  const limited = await callTool('check_spend', {
    amount: 500,
    spendConfig: { type: 'limit', maxPerTx: 100 },
  });
  assert.equal(limited.allowed, false);

  const ok = await callTool('check_spend', {
    amount: 50,
    spendConfig: { type: 'limit', maxPerTx: 100 },
  });
  assert.equal(ok.allowed, true);
});

test('takeover_guard blocks when human took control mid-operation', async () => {
  const blocked = await callTool('takeover_guard', {
    before: { type: 'unlimited' },
    after: { type: 'require-approval' },
  });
  assert.equal(blocked.safe, false);

  const safe = await callTool('takeover_guard', {
    before: { type: 'unlimited' },
    after: { type: 'unlimited' },
  });
  assert.equal(safe.safe, true);
});

test('generate_keypair derives chain addresses WITHOUT exposing the private key (INV-001)', async () => {
  const { generateAddress } = await import('aegis-vault');
  const out = await callTool('generate_keypair', {});
  assert.equal(out.success, true);
  assert.equal(out.publicKeyHex.length, 2624);
  assert.equal('privateKeyHex' in out, false, 'raw private key must never be emitted (INV-001)');
  // nexus address must be reproducible from the public key alone
  assert.equal(out.address, generateAddress(Buffer.from(out.publicKeyHex, 'hex')));
  assert.equal(out.chainAddresses.nexus, out.address);
  assert.match(out.chainAddresses.eth, /^0x[0-9a-fA-F]{40}$/);
  assert.ok(out.chainAddresses.sol && out.chainAddresses.sol.length > 0);
});

test('register_agent WITHOUT session identity REQUIRES a real password (INV-001)', async () => {
  // The `session` object is a module-level singleton shared by every server
  // instance, and the earlier generate_agent_keys test already populated it.
  // Import server.js under a distinct module URL to get a FRESH module state
  // (wallet: null) so the password-guard branch is actually exercised.
  const freshServer = await import('../src/server.js?inv001');
  const s = freshServer.createServer();
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await s.connect(st);
  const c = new Client({ name: 'inv001-client', version: '1.0.0' }, { capabilities: {} });
  await c.connect(ct);

  // No password at all → must fail closed, never a silent default identity.
  const res = await c.callTool({ name: 'register_agent', arguments: { name: 'inv001-no-pass' } });
  const out = JSON.parse(res.content[0].text);
  assert.equal(out.success, false);
  assert.match(out.error, /password is required/);
  assert.equal(res.isError, true, 'must surface as a tool error');

  // Too-short password → must also fail closed.
  const short = await c.callTool({ name: 'register_agent', arguments: { name: 'inv001-short', password: 'short' } });
  const shortOut = JSON.parse(short.content[0].text);
  assert.equal(shortOut.success, false);
  assert.match(shortOut.error, /password is required/);

  await c.close();
  await s.close();
});

test('claim_task signs via the ISOLATED signer and the signature verifies (P0-3)', async () => {
  // Local mock API to capture the signed claim request (avoids the live network).
  const http = await import('node:http');
  let captured = null;
  const mock = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      try { captured = JSON.parse(body); } catch { captured = null; }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ success: true }));
    });
  });
  await new Promise((r) => mock.listen(0, r));
  const port = mock.address().port;
  process.env.NEXUSGENESIS_API = `http://127.0.0.1:${port}`;

  try {
    // Fresh module state so this session is independent of earlier tests.
    const fresh = await import(`../src/server.js?p03-${port}`);
    const s = fresh.createServer();
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await s.connect(st);
    const c = new Client({ name: 'p03-client', version: '1.0.0' }, { capabilities: {} });
    await c.connect(ct);

    const gen = await c.callTool({ name: 'generate_agent_keys', arguments: { password: 'agent-secret-123', metadata: { name: 'p03-agent' } } });
    const genOut = JSON.parse(gen.content[0].text);
    assert.equal(genOut.signing, 'isolated-signer (P0-3)', 'default write path must use the isolated signer');

    await c.callTool({ name: 'claim_task', arguments: { taskId: 't-1' } });
    await new Promise((r) => setTimeout(r, 500));
    assert.ok(captured, 'claim request must reach the mock API');
    assert.equal(captured.agent, 'p03-agent');
    assert.ok(captured.signature && captured.nonce && captured.timestamp, 'signed claim must carry signature+nonce+timestamp');

    // Reconstruct the EXACT payload the server verifies (verifyTaskSignature):
    // { action, taskId, agent, timestamp, nonce } — and check the signer's sig.
    const { verify } = await import('aegis-vault');
    const payload = JSON.stringify({
      action: 'claim', taskId: 't-1', agent: 'p03-agent',
      timestamp: captured.timestamp, nonce: captured.nonce,
    });
    const ok = await verify(payload, Buffer.from(captured.signature, 'hex'), Buffer.from(genOut.publicKeyHex, 'hex'));
    assert.equal(ok, true, 'signature from the isolated signer must verify over the canonical payload');
    await c.close();
    await s.close();
  } finally {
    delete process.env.NEXUSGENESIS_API;
    await new Promise((r) => mock.close(r));
  }
});

test('forum writes (create_topic) sign via the ISOLATED signer (P0-3)', async () => {
  const http = await import('node:http');
  let captured = null;
  const mock = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      try { captured = JSON.parse(body); } catch { captured = null; }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ success: true, topic: { id: 't-1' } }));
    });
  });
  await new Promise((r) => mock.listen(0, r));
  const port = mock.address().port;
  process.env.NEXUSGENESIS_API = `http://127.0.0.1:${port}`;

  try {
    const fresh = await import(`../src/server.js?p03forum-${port}`);
    const s = fresh.createServer();
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await s.connect(st);
    const c = new Client({ name: 'p03-forum-client', version: '1.0.0' }, { capabilities: {} });
    await c.connect(ct);

    const gen = await c.callTool({ name: 'generate_agent_keys', arguments: { password: 'agent-secret-123', metadata: { name: 'p03-forum-agent' } } });
    const genOut = JSON.parse(gen.content[0].text);
    assert.equal(genOut.signing, 'isolated-signer (P0-3)');

    await c.callTool({ name: 'create_topic', arguments: { title: 'hi', body: 'hello world' } });
    await new Promise((r) => setTimeout(r, 500));
    assert.ok(captured, 'create_topic request must reach the mock API');
    assert.equal(captured.agent, 'p03-forum-agent');
    assert.ok(captured.signature && captured.nonce && captured.timestamp, 'forum write must be PQC-signed');

    // Server-side contract (buildSignedFields): { agent, action, timestamp, nonce }.
    const { verify } = await import('aegis-vault');
    const payload = JSON.stringify({
      agent: 'p03-forum-agent', action: 'create_topic',
      timestamp: captured.timestamp, nonce: captured.nonce,
    });
    const ok = await verify(payload, Buffer.from(captured.signature, 'hex'), Buffer.from(genOut.publicKeyHex, 'hex'));
    assert.equal(ok, true, 'forum signature must come from the isolated signer and verify');
    await c.close();
    await s.close();
  } finally {
    delete process.env.NEXUSGENESIS_API;
    await new Promise((r) => mock.close(r));
  }
});

test('signer spawn failure downgrades EXPLICITLY to the lazy in-process wallet (P0-3)', async () => {
  const http = await import('node:http');
  let captured = null;
  const mock = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      try { captured = JSON.parse(body); } catch { captured = null; }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ success: true }));
    });
  });
  await new Promise((r) => mock.listen(0, r));
  const port = mock.address().port;
  process.env.NEXUSGENESIS_API = `http://127.0.0.1:${port}`;
  // Simulate an environment where the signer subprocess cannot be spawned.
  process.env.NEXUSGENESIS_SIGNER_DISABLE = '1';
  // External review 2026-08-24: the in-process downgrade is gated and fails
  // closed by default — this test exercises the EXPLICIT opt-in path.
  process.env.MCP_ALLOW_INPROCESS_WALLET = '1';

  try {
    const fresh = await import(`../src/server.js?p03fb-${port}`);
    const s = fresh.createServer();
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await s.connect(st);
    const c = new Client({ name: 'p03-fb-client', version: '1.0.0' }, { capabilities: {} });
    await c.connect(ct);

    const gen = await c.callTool({ name: 'generate_agent_keys', arguments: { password: 'agent-secret-123', metadata: { name: 'p03-fb-agent' } } });
    const genOut = JSON.parse(gen.content[0].text);
    // The downgrade must be VISIBLE to the caller, never silent.
    assert.equal(genOut.signing, 'in-process-wallet (fallback)');

    // The fallback wallet materializes lazily and the write path still works.
    await c.callTool({ name: 'claim_task', arguments: { taskId: 't-9' } });
    await new Promise((r) => setTimeout(r, 500));
    assert.ok(captured, 'claim request must reach the mock API');
    assert.ok(captured.signature && captured.nonce && captured.timestamp);

    const { verify } = await import('aegis-vault');
    const payload = JSON.stringify({
      action: 'claim', taskId: 't-9', agent: 'p03-fb-agent',
      timestamp: captured.timestamp, nonce: captured.nonce,
    });
    const ok = await verify(payload, Buffer.from(captured.signature, 'hex'), Buffer.from(genOut.publicKeyHex, 'hex'));
    assert.equal(ok, true, 'fallback wallet signature must verify');
    await c.close();
    await s.close();
  } finally {
    delete process.env.NEXUSGENESIS_API;
    delete process.env.NEXUSGENESIS_SIGNER_DISABLE;
    delete process.env.MCP_ALLOW_INPROCESS_WALLET;
    await new Promise((r) => mock.close(r));
  }
});

test('in-process wallet downgrade is BLOCKED by default (fail-closed, external review 2026-08-24)', async () => {
  const http = await import('node:http');
  let captured = null;
  const mock = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      try { captured = JSON.parse(body); } catch { captured = null; }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ success: true }));
    });
  });
  await new Promise((r) => mock.listen(0, r));
  const port = mock.address().port;
  process.env.NEXUSGENESIS_API = `http://127.0.0.1:${port}`;
  // Signer unavailable AND no explicit opt-in → the key must NOT materialize.
  process.env.NEXUSGENESIS_SIGNER_DISABLE = '1';
  assert.equal(process.env.MCP_ALLOW_INPROCESS_WALLET, undefined, 'gate must default to unset');

  try {
    const fresh = await import(`../src/server.js?p03block-${port}`);
    const s = fresh.createServer();
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await s.connect(st);
    const c = new Client({ name: 'p03-block-client', version: '1.0.0' }, { capabilities: {} });
    await c.connect(ct);

    await c.callTool({ name: 'generate_agent_keys', arguments: { password: 'agent-secret-123', metadata: { name: 'p03-block-agent' } } });

    // The write must fail closed instead of silently materializing the key.
    const res = await c.callTool({ name: 'claim_task', arguments: { taskId: 't-block' } });
    const out = JSON.parse(res.content[0].text);
    assert.equal(out.success, false, 'claim must fail when the downgrade is not opted in');
    assert.match(out.error, /INPROCESS_WALLET_BLOCKED|MCP_ALLOW_INPROCESS_WALLET/, 'error must point at the fail-closed gate');
    assert.equal(captured, null, 'no signed request may reach the API without a signer');
    await c.close();
    await s.close();
  } finally {
    delete process.env.NEXUSGENESIS_API;
    delete process.env.NEXUSGENESIS_SIGNER_DISABLE;
    delete process.env.MCP_ALLOW_INPROCESS_WALLET;
    await new Promise((r) => mock.close(r));
  }
});