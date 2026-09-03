/**
 * transport-distributed.test.js — Sprint 6 T2：replay guard 共享化（多实例）
 *
 * 验收（Sprint6计划 T2）：
 *   - 双实例共享 sqlite：实例 A record (s,n) → 实例 B 判定重放（claim 全族恰好一次）。
 *   - 两个 inbound verifier（同 self、共享 store）对同一信封：首个 ok、次个 replay_detected
 *     ——Sprint 4 基线下两实例各自窗口各放行一次的漏洞被关闭。
 *   - 重启（新连接同文件）窗口不丢：重放仍拒。
 *   - 容量：超 maxEntries → 先清过期（retention）仍超 → FIFO 硬上限。
 *   - 单机默认路径 legacy 容忍：损坏文件 → 显式告警 + degraded + 空窗口自愈（验签/身份不受影响）。
 *   - 共享模式 fail-closed：后端操作错误直接传播（不静默退化独立窗口）。
 *   - instanceFamilyId：同 sqlite 文件同族（审计对账）。
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createIdentityDirectory,
  createReplayStore,
  createInboundVerifier,
  createMessageEnvelope,
  createSqliteStore,
  sqliteAvailable,
} from '../src/index.js';

const sign = (bytes) => 'sig-' + [...bytes].reduce((a, b) => (a * 31 + (b & 0xff)) >>> 0, 7).toString(16);
const verify = (bytes, signature) => signature === sign(bytes);

const SENDER = 'ng1-agent-a';
const TARGET = 'ng1-service-b';
const PAYLOAD = { type: 'task_claim', taskId: 'T-42' };

let dir;
const openBackends = [];
before(() => { dir = mkdtempSync(join(tmpdir(), 't2-dist-')); });
after(() => {
  // Windows：未关闭的 sqlite 连接锁文件 → 先关连接再清目录。
  for (const b of openBackends) { try { b.close(); } catch { /* already closed */ } }
  try { rmSync(dir, { recursive: true, force: true }); } catch { /* best-effort */ }
});

const sqliteFile = (name) => join(dir, name);
/** 开共享 sqlite backend（登记生命周期，after 统一关闭）。 */
function openSharedBackend(name) {
  const backend = createSqliteStore({ file: sqliteFile(name) });
  openBackends.push(backend);
  return backend;
}
function makeDirectory() {
  const directory = createIdentityDirectory();
  directory.register({ id: SENDER, publicKey: '0xpub', verifier: verify });
  return directory;
}

test('T2.1 双实例共享 sqlite：record 全族恰好一次（跨实例重放被拒）', { skip: !sqliteAvailable }, () => {
  const storeA = createReplayStore({ store: openSharedBackend('replay-shared-1.sqlite') });
  const storeB = createReplayStore({ store: openSharedBackend('replay-shared-1.sqlite') });
  try {
    assert.equal(storeA.backendType, 'sqlite');
    assert.equal(storeA.degraded, false);
    assert.equal(storeA.instanceFamilyId(), storeB.instanceFamilyId(), '同 sqlite 文件 → 同族（审计对账）');

    assert.equal(storeA.record(`${SENDER}:n1`), true, '实例 A 首次登记成功');
    assert.equal(storeB.record(`${SENDER}:n1`), false, '实例 B 同 key → 重放被拒（跨实例可见）');
    assert.equal(storeB.has(`${SENDER}:n1`), true);
    assert.equal(storeB.size, 1);

    // 反方向同样成立。
    assert.equal(storeB.record(`${SENDER}:n2`), true);
    assert.equal(storeA.record(`${SENDER}:n2`), false);
    assert.equal(storeA.size, 2, 'A 也能看到 B 登记的 key');
  } finally { /* backend 生命周期由 after() 统一关闭 */ }
});

test('T2.2 两个 inbound verifier 共享窗口：同信封首 ok 次 replay_detected（核心验收）', { skip: !sqliteAvailable }, () => {
  const replayStore = createReplayStore({ store: openSharedBackend('replay-shared-2.sqlite') });
  const directory = makeDirectory();

  // 同一服务的两个"实例"：同 self、同身份目录、共享 replay store。
  const verifierA = createInboundVerifier({ directory, self: TARGET, replayStore });
  const verifierB = createInboundVerifier({ directory, self: TARGET, replayStore });

  const envelope = createMessageEnvelope({
    sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, timestamp: Date.now(), nonce: 'nonce-1',
  });

  const first = verifierA({ envelope });
  assert.equal(first.ok, true, '实例 A 首次放行');

  // Sprint 4 基线（各实例独立窗口）下，B 会再次放行——共享化后必须拒。
  const second = verifierB({ envelope });
  assert.equal(second.ok, false);
  assert.equal(second.error, 'replay_detected');

  // 不同 nonce 的合法新信封在任一实例仍正常放行。
  const fresh = createMessageEnvelope({
    sender: SENDER, target: TARGET, payload: PAYLOAD, signer: sign, timestamp: Date.now(), nonce: 'nonce-2',
  });
  assert.equal(verifierB({ envelope: fresh }).ok, true);
});

test('T2.3 共享窗口重启不丢：新连接（新实例族）重放仍拒', { skip: !sqliteAvailable }, () => {
  const storeA = createReplayStore({ store: openSharedBackend('replay-shared-3.sqlite') });
  storeA.record(`${SENDER}:n1`);

  const reopened = createReplayStore({ store: openSharedBackend('replay-shared-3.sqlite') });
  assert.equal(reopened.record(`${SENDER}:n1`), false, '重启（新连接）后重放仍拒');
  assert.equal(reopened.has(`${SENDER}:n1`), true);
});

test('T2.4 容量：超 maxEntries → retention 清过期 + FIFO 硬上限兜底', { skip: !sqliteAvailable }, () => {
  const store = createReplayStore({ store: openSharedBackend('replay-cap.sqlite'), maxEntries: 3 });
  store.record(`${SENDER}:n1`);
  store.record(`${SENDER}:n2`);
  store.record(`${SENDER}:n3`);
  store.record(`${SENDER}:n4`); // 触发 enforceCapacity：全部新鲜 → FIFO 淘汰 n1
  assert.equal(store.size, 3);
  assert.equal(store.has(`${SENDER}:n1`), false, 'FIFO 淘汰最旧');
  assert.equal(store.has(`${SENDER}:n4`), true);
  // 淘汰后的 key 若再到达：timestamp 已老（> maxAgeMs）→ 信封新鲜度检查先行拒绝，
  // 窗口容量语义与单机基线一致。
});

test('T2.5 单机默认路径（不注入 store）：损坏文件 → 显式告警 + degraded + 空窗口自愈', () => {
  const file = join(dir, `local-corrupt-${Date.now()}.json`);
  writeFileSync(file, '{corrupted', 'utf8');

  const store = createReplayStore({ file });
  assert.equal(store.backendType, 'local');
  assert.equal(store.degraded, true, '损坏被显式标记（不静默）');
  assert.equal(store.size, 0, '空窗口（仅重放检测粒度降级）');
  assert.equal(store.has(`${SENDER}:x`), false);

  // 自愈：首条记录后文件重建，可再次加载。
  assert.equal(store.record(`${SENDER}:x`), true);
  const healed = createReplayStore({ file });
  assert.equal(healed.degraded, false, '自愈后的文件可正常加载');
  assert.equal(healed.record(`${SENDER}:x`), false, '自愈窗口内重放仍拒');
});

test('T2.6 共享模式 fail-closed：后端操作错误直接传播（不静默退化独立窗口）', { skip: !sqliteAvailable }, () => {
  const backend = createSqliteStore({ file: sqliteFile('replay-failclosed.sqlite') });
  const store = createReplayStore({ store: backend });
  store.record(`${SENDER}:n1`);
  backend.close(); // 模拟后端不可用
  assert.throws(() => store.record(`${SENDER}:n2`), undefined, '后端关闭 → record 抛错（fail-closed）');
});

test('T2.7 单机默认路径与共享路径互不串扰：local 文件不声明为共享族', () => {
  const file = join(dir, 'local-only.json');
  const a = createReplayStore({ file });
  const b = createReplayStore({ file });
  assert.equal(a.backendType, 'local');
  // local 后端即使两实例同文件也是"最后写胜出"非原子共享——族 id 相同（同文件）
  // 但语义按单机文档化；本测试固化该边界，防止误当共享用。
  assert.equal(a.instanceFamilyId(), b.instanceFamilyId());
});
