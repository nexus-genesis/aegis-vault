/**
 * 验证 agent-sdk forum 模块：
 *  1. buildSignedFields 与后端 verifyAgentIdentity 的签名原文（key 顺序）严格一致
 *  2. signForumAction 产出的签名可被 PQCWallet.verify 验证通过
 *  3. 每个操作唯一 nonce 防重放
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ForumClient, signForumAction, buildSignedFields } from '../src/forum.js';
import { createAgentIdentity, recoverAgentIdentity } from '../src/keys.js';
import { PQCWallet } from 'aegis-vault';

// —— 与后端 verifyAgentIdentity 期望的 signedFields 完全一致的镜像 ——
function backendSignedFields(action, { agent, topicId, vote, timestamp, nonce }) {
  if (action === 'vote') return { topicId, agent, vote, timestamp, nonce };
  if (action === 'create_topic') return { agent, action: 'create_topic', timestamp, nonce };
  return { agent, action: 'add_post', topicId, timestamp, nonce };
}

test('buildSignedFields 与后端 verifyAgentIdentity 签名原文严格一致', () => {
  const fields = { agent: 'swarm-atlas-1', topicId: 'topic_x', vote: 'yes', timestamp: 123, nonce: 'n' };

  for (const action of ['vote', 'create_topic', 'add_post']) {
    const mine = buildSignedFields(action, fields);
    const backend = backendSignedFields(action, fields);
    assert.equal(
      JSON.stringify(mine),
      JSON.stringify(backend),
      `${action}: SDK 签名原文应与后端一致`
    );
  }
});

test('signForumAction 签名可被 PQCWallet.verify 验证通过', async () => {
  const identity = await createAgentIdentity({ password: 'test-password-123' });
  const wallet = recoverAgentIdentity(identity.envelope, 'test-password-123');
  assert.ok(wallet, '应能恢复钱包');

  const publicKeyHex = identity.publicKeyHex;

  // 镜像后端 verifyAgentIdentity：PQCWallet.verify(signedData, signature, publicKeyBuffer)
  // create_topic
  const a1 = await signForumAction(wallet, 'create_topic', { agent: identity.address });
  const valid = await PQCWallet.verify(
    JSON.stringify(buildSignedFields('create_topic', { agent: identity.address, ...a1 })),
    a1.signature,
    Buffer.from(publicKeyHex, 'hex')
  );
  assert.equal(valid, true, 'create_topic 签名应通过验证');

  // vote
  const a2 = await signForumAction(wallet, 'vote', { agent: identity.address, topicId: 't1', vote: 'yes' });
  const validVote = await PQCWallet.verify(
    JSON.stringify(buildSignedFields('vote', { agent: identity.address, topicId: 't1', vote: 'yes', ...a2 })),
    a2.signature,
    Buffer.from(publicKeyHex, 'hex')
  );
  assert.equal(validVote, true, 'vote 签名应通过验证');

  // add_post
  const a3 = await signForumAction(wallet, 'add_post', { agent: identity.address, topicId: 't1' });
  const validPost = await PQCWallet.verify(
    JSON.stringify(buildSignedFields('add_post', { agent: identity.address, topicId: 't1', ...a3 })),
    a3.signature,
    Buffer.from(publicKeyHex, 'hex')
  );
  assert.equal(validPost, true, 'add_post 签名应通过验证');
});

test('每次签名生成唯一 nonce（防重放）', async () => {
  const identity = await createAgentIdentity({ password: 'test-password-456' });
  const wallet = recoverAgentIdentity(identity.envelope, 'test-password-456');

  const seen = new Set();
  for (let i = 0; i < 5; i++) {
    const { nonce } = await signForumAction(wallet, 'create_topic', { agent: identity.address });
    assert.ok(!seen.has(nonce), 'nonce 不应重复');
    seen.add(nonce);
  }
});

test('ForumClient 构造要求 wallet', () => {
  assert.throws(() => new ForumClient({}), /requires a wallet/);
});

test('ForumClient 写方法 POST 带签名字段', async () => {
  const identity = await createAgentIdentity({ password: 'test-password-789' });
  const wallet = recoverAgentIdentity(identity.envelope, 'test-password-789');

  const posted = [];
  const fakeTransport = {
    get: async () => ({ ok: true }),
    post: async (path, body) => { posted.push({ path, body }); return { ok: true, body }; }
  };
  const client = new ForumClient({ wallet, transport: fakeTransport });

  await client.createTopic({ agent: identity.address, title: 'Hi', body: 'world' });
  await client.addPost('topic_a', { agent: identity.address, body: 'reply' });
  await client.vote('topic_a', { agent: identity.address, vote: 'yes' });

  assert.equal(posted.length, 3);
  for (const { body } of posted) {
    assert.ok(body.signature, '应带 signature');
    assert.ok(body.timestamp, '应带 timestamp');
    assert.ok(body.nonce, '应带 nonce');
  }

  // create_topic body 应含标题/正文
  assert.equal(posted[0].body.title, 'Hi');
  // vote body 应含投票
  assert.equal(posted[2].body.vote, 'yes');
});
