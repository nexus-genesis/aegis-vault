/**
 * store-interface.test.js — Sprint 6 T1：共享状态抽象（local / sqlite 双后端）
 *
 * 验收（Sprint6计划 T1）：
 *   - 同一套 store 语义测试在 local 与 sqlite 后端都跑通（同构接口）。
 *   - claim 恰好一次：双连接共享同一 sqlite 文件（模拟双实例），同 key 只有一个成功。
 *   - writeAtomically 并发无丢失更新：双连接交叉 read-modify-write 计数器，终值=总和。
 *   - fail-closed：损坏 local 文件 / 非法 sqlite 路径 / redis 占位 / sqlite 缺 file → 构造抛错，
 *     绝不静默回退空态。
 *   - local 持久化重启恢复（新实例读同一文件）；sqlite 跨实例可见。
 *   - resolveStateBackend auto：.sqlite/.db → sqlite；其他 → local；显式 kind 按字面。
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createLocalStore,
  createSqliteStore,
  createRedisStore,
  resolveStateBackend,
  assertValidStoreKey,
  sqliteAvailable,
} from '../src/store-interface.js';

let dir;
before(() => { dir = mkdtempSync(join(tmpdir(), 'store-if-')); });
after(() => { rmSync(dir, { recursive: true, force: true }); });

const sqliteFile = () => join(dir, `shared-${randomId()}.sqlite`);
function randomId() { return Math.random().toString(36).slice(2, 10); }

/** 同构语义矩阵：local 与 sqlite 后端跑同一套断言（T1 验收核心）。 */
function semanticMatrix(name, makeStore) {
  test(`[${name}] read/write/has/keys/list/delete roundtrip`, () => {
    const s = makeStore();
    try {
      assert.equal(s.read('replay:a:1'), null, 'missing key → null');
      assert.equal(s.has('replay:a:1'), false);

      const v1 = s.write('replay:a:1', { ts: 100 });
      assert.equal(v1.version, 1);
      assert.deepEqual(s.read('replay:a:1'), { ts: 100 });
      assert.equal(s.has('replay:a:1'), true);

      const v2 = s.write('replay:a:1', { ts: 200 });
      assert.equal(v2.version, 2, '覆盖写版本单调递增');
      assert.deepEqual(s.read('replay:a:1'), { ts: 200 });

      s.write('replay:b:2', { ts: 300 });
      s.write('sim:0xdigest', { accountId: 'acc1' });
      assert.deepEqual(s.keys('replay:'), ['replay:a:1', 'replay:b:2'], 'prefix keys');
      assert.deepEqual(Object.keys(s.list('replay:')), ['replay:a:1', 'replay:b:2']);
      assert.deepEqual(s.list('sim:')['sim:0xdigest'], { accountId: 'acc1' });

      // read 返回深拷贝（外部修改不污染 store）。
      const got = s.read('sim:0xdigest');
      got.accountId = 'MUTATED';
      assert.deepEqual(s.read('sim:0xdigest'), { accountId: 'acc1' });

      assert.deepEqual(s.delete('replay:b:2'), { deleted: true });
      assert.deepEqual(s.delete('replay:b:2'), { deleted: false }, '重复 delete → false');
      assert.equal(s.has('replay:b:2'), false);
    } finally { s.close(); }
  });

  test(`[${name}] claim 恰好一次（同 key 第二次 claimed:false）`, () => {
    const s = makeStore();
    try {
      assert.deepEqual(s.claim('replay:s:nonce1', { ts: 1 }), { claimed: true });
      assert.deepEqual(s.claim('replay:s:nonce1', { ts: 2 }), { claimed: false }, '重放 key 不可二次登记');
      assert.deepEqual(s.read('replay:s:nonce1'), { ts: 1 }, '首个登记者的值胜出');
      assert.deepEqual(s.claim('replay:s:nonce2', { ts: 3 }), { claimed: true }, '不同 key 各自恰好一次');
    } finally { s.close(); }
  });

  test(`[${name}] writeAtomically：无初值 → mutate(null)；RMW 版本递增；返回深拷贝`, () => {
    const s = makeStore();
    try {
      const r1 = s.writeAtomically('state:acc1', (cur) => ({ count: (cur?.count ?? 0) + 1 }));
      assert.deepEqual(r1.value, { count: 1 });
      assert.equal(r1.version, 1);
      const r2 = s.writeAtomically('state:acc1', (cur) => ({ count: cur.count + 1 }));
      assert.deepEqual(r2.value, { count: 2 });
      assert.equal(r2.version, 2);
      r1.value.count = 999; // 返回值是拷贝，改不动 store
      assert.deepEqual(s.read('state:acc1'), { count: 2 });
    } finally { s.close(); }
  });

  test(`[${name}] writeAtomically expectedVersion：匹配 → 成功；不匹配 → STORE_CAS_CONFLICT`, () => {
    const s = makeStore();
    try {
      s.write('state:acc2', { n: 1 }); // v1
      const ok = s.writeAtomically('state:acc2', (cur) => ({ n: cur.n + 1 }), { expectedVersion: 1 });
      assert.equal(ok.version, 2);
      assert.throws(
        () => s.writeAtomically('state:acc2', (cur) => ({ n: cur.n + 1 }), { expectedVersion: 1 }),
        (e) => e.code === 'STORE_CAS_CONFLICT',
      );
      // 冲突后状态未被污染。
      assert.deepEqual(s.read('state:acc2'), { n: 2 });
    } finally { s.close(); }
  });

  test(`[${name}] purgeExpired 按 updated_at 清窗口（replay 语义）`, () => {
    const s = makeStore();
    try {
      s.claim('replay:old:1', { ts: 1 });
      const fresh = s.claim('replay:new:2', { ts: 2 });
      assert.equal(fresh.claimed, true);
      const now = Date.now();
      // old 条目 updated_at < now-50 → 被清；fresh 不动。
      const { purged } = s.purgeExpired(now - 50);
      // 两条记录都是刚写入的，updated_at ≥ now-50 → 0 被清（自洽性检查）。
      assert.equal(purged, 0);
      assert.equal(s.has('replay:old:1'), true);
      assert.equal(s.has('replay:new:2'), true);
      // 用未来边界清掉全部。
      const p2 = s.purgeExpired(now + 10_000);
      assert.ok(p2.purged >= 2, `应清掉至少 2 条（实际 ${p2.purged}）`);
      assert.equal(s.has('replay:old:1'), false);
      assert.equal(s.has('replay:new:2'), false);
    } finally { s.close(); }
  });

  test(`[${name}] evictOldest 容量硬上限：最旧优先 FIFO`, () => {
    const s = makeStore();
    try {
      // 先放一条非 prefix 键，验证 evict 只作用于 prefix 内。
      s.write('other:key', { x: 1 });
      assert.deepEqual(s.evictOldest('replay:', 3), { evicted: 0 }, '未超限 → 不动');
      for (let i = 1; i <= 4; i += 1) s.claim(`replay:s:n${i}`, { i });
      assert.deepEqual(s.evictOldest('replay:', 3), { evicted: 1 }, '4 → 3 淘汰 1 条');
      // 最旧（首登记者）被淘汰——local 按插入序、sqlite 按 updated_at+rowid，均为首条。
      assert.equal(s.has('replay:s:n1'), false, '最旧被淘汰');
      assert.equal(s.has('replay:s:n4'), true, '最新保留');
      assert.equal(s.has('other:key'), true, 'prefix 外不受影响');
      assert.equal(s.keys('replay:').length, 3);
    } finally { s.close(); }
  });

  test(`[${name}] key/value 校验 fail-closed`, () => {
    const s = makeStore();
    try {
      assert.throws(() => s.read(''), /invalid store key/);
      assert.throws(() => s.read(null), /invalid store key/);
      assert.throws(() => s.write('k', undefined), /JSON-serializable/);
      assert.throws(() => s.claim('k', () => {}), /JSON-serializable/); // 函数不可序列化
    } finally { s.close(); }
  });

  test(`[${name}] instanceFamilyId：同源共享 / 不同源隔离`, () => {
    // 每次调用 makeStore() 建新 store；family 语义由后端类型决定：
    // local(纯内存) 每实例独立；sqlite(文件) 同文件同族。
    const a = makeStore();
    const b = makeStore();
    try {
      if (a.type === 'sqlite') {
        assert.equal(a.instanceFamilyId(), b.instanceFamilyId(), '同 sqlite 文件 → 同族');
      } else if (a.instanceFamilyId().startsWith('memory:')) {
        assert.notEqual(a.instanceFamilyId(), b.instanceFamilyId(), 'local 纯内存 → 各自独立族');
      }
      assert.notEqual(a.instanceId(), b.instanceId(), '实例 id 唯一');
    } finally { a.close(); b.close(); }
  });
}

// local（纯内存 / JSON 持久化）与 sqlite（:memory:）跑同一矩阵。
semanticMatrix('local-memory', () => createLocalStore());
// sqlite 矩阵仅在 node:sqlite 可用时注册（Node < 22.5 skip，保留 18/20 腿绿）。
if (sqliteAvailable) {
  semanticMatrix('sqlite-memory', () => createSqliteStore({ file: ':memory:' }));
}

// ── local 持久化：重启恢复（新实例读同一文件） ─────────────────────────────

test('[local-file] 持久化 + 重启恢复：claim 状态跨实例存活', () => {
  const file = join(dir, `local-${randomId()}.json`);
  const a = createLocalStore({ file });
  a.claim('replay:s:n1', { ts: 1 });
  a.write('state:acc', { count: 7 });
  a.close();

  const b = createLocalStore({ file }); // "重启"
  try {
    assert.equal(b.has('replay:s:n1'), true, '重启后重放窗口不丢');
    assert.deepEqual(b.claim('replay:s:n1', { ts: 2 }), { claimed: false }, '重启后重放仍拒');
    assert.deepEqual(b.read('state:acc'), { count: 7 });
  } finally { b.close(); }
});

test('[local-file] 损坏文件 → 构造抛错（fail-closed，不静默空态）', () => {
  const file = join(dir, `corrupt-${randomId()}.json`);
  writeFileSync(file, '{not json', 'utf8');
  assert.throws(() => createLocalStore({ file }), /corrupted \(fail-closed\)/);
});

// ── sqlite 跨实例（双连接共享同一文件 = 模拟双实例） ────────────────────────

test('[sqlite-shared] 双实例共享：claim 全族恰好一次', { skip: !sqliteAvailable }, () => {
  const file = sqliteFile();
  const a = createSqliteStore({ file });
  const b = createSqliteStore({ file });
  try {
    assert.deepEqual(a.claim('replay:agent:nonce9', { ts: 1 }), { claimed: true });
    assert.deepEqual(b.claim('replay:agent:nonce9', { ts: 2 }), { claimed: false }, '实例 B 重放被拒（跨实例可见）');
    assert.equal(b.has('replay:agent:nonce9'), true);
    // 反方向同样成立。
    assert.deepEqual(b.claim('replay:agent:nonce10', { ts: 3 }), { claimed: true });
    assert.deepEqual(a.claim('replay:agent:nonce10', { ts: 4 }), { claimed: false });
  } finally { a.close(); b.close(); }
});

test('[sqlite-shared] 双实例并发 RMW 无丢失更新（计数器交叉递增）', { skip: !sqliteAvailable }, () => {
  const file = sqliteFile();
  const a = createSqliteStore({ file });
  const b = createSqliteStore({ file });
  try {
    a.write('state:counter', { n: 0 });
    // 每实例各做 25 次 read-modify-write，串行交叉（同进程内模拟并发竞争路径）。
    for (let i = 0; i < 25; i += 1) {
      a.writeAtomically('state:counter', (cur) => ({ n: cur.n + 1 }));
      b.writeAtomically('state:counter', (cur) => ({ n: cur.n + 1 }));
    }
    assert.deepEqual(a.read('state:counter'), { n: 50 }, '50 次 RMW 零丢失');
    assert.deepEqual(b.read('state:counter'), { n: 50 }, '双实例读到一致终值');
  } finally { a.close(); b.close(); }
});

test('[sqlite-shared] purgeExpired 跨实例生效', { skip: !sqliteAvailable }, () => {
  const file = sqliteFile();
  const a = createSqliteStore({ file });
  const b = createSqliteStore({ file });
  try {
    a.claim('replay:x:1', { ts: 1 });
    b.claim('replay:x:2', { ts: 2 });
    const now = Date.now();
    const { purged } = a.purgeExpired(now + 10_000);
    assert.equal(purged, 2, '任一实例清理，全族生效');
    assert.equal(b.has('replay:x:1'), false);
  } finally { a.close(); b.close(); }
});

// ── fail-closed 与解析规则 ────────────────────────────────────────────────

test('createRedisStore 是 SPI 占位 → 调用即抛（防误用空壳）', () => {
  assert.throws(() => createRedisStore({ url: 'redis://x' }), /SPI placeholder.*Not implemented/);
});

test('sqlite 缺 file / 非法路径 → 构造抛错', { skip: !sqliteAvailable }, () => {
  assert.throws(() => createSqliteStore({}), /requires \{ file \}/);
  // 父路径本身是个文件 → mkdir/open 失败 → fail-closed。
  const notADir = join(dir, `notadir-${randomId()}.txt`);
  writeFileSync(notADir, 'x', 'utf8');
  assert.throws(() => createSqliteStore({ file: join(notADir, 'sub.sqlite') }), /fail-closed/);
});

test('resolveStateBackend auto：.sqlite/.db → sqlite；其他 → local；显式 kind 按字面', { skip: !sqliteAvailable }, () => {
  const envB = process.env.NEXUS_STORE_BACKEND;
  const envF = process.env.NEXUS_SHARED_STATE_FILE;
  try {
    delete process.env.NEXUS_STORE_BACKEND;
    delete process.env.NEXUS_SHARED_STATE_FILE;

    let s = resolveStateBackend({ file: join(dir, 'a.sqlite') });
    assert.equal(s.type, 'sqlite'); s.close();

    s = resolveStateBackend({ file: join(dir, 'b.db') });
    assert.equal(s.type, 'sqlite'); s.close();

    s = resolveStateBackend({ file: join(dir, 'c.json') });
    assert.equal(s.type, 'local'); s.close();

    s = resolveStateBackend({});
    assert.equal(s.type, 'local'); s.close();

    s = resolveStateBackend({ backend: 'local', file: join(dir, 'd.sqlite') });
    assert.equal(s.type, 'local', '显式 local 优先于扩展名'); s.close();

    assert.throws(() => resolveStateBackend({ backend: 'sqlite' }), /requires a file/);

    // env 回退来源。
    process.env.NEXUS_SHARED_STATE_FILE = join(dir, `env-${randomId()}.sqlite`);
    s = resolveStateBackend({});
    assert.equal(s.type, 'sqlite', 'auto + env .sqlite → sqlite'); s.close();

    process.env.NEXUS_STORE_BACKEND = 'local';
    process.env.NEXUS_SHARED_STATE_FILE = join(dir, `env-${randomId()}.json`);
    s = resolveStateBackend({});
    assert.equal(s.type, 'local', '显式 env local 覆盖 auto 扩展名分流'); s.close();
  } finally {
    if (envB === undefined) delete process.env.NEXUS_STORE_BACKEND; else process.env.NEXUS_STORE_BACKEND = envB;
    if (envF === undefined) delete process.env.NEXUS_SHARED_STATE_FILE; else process.env.NEXUS_SHARED_STATE_FILE = envF;
  }
});

test('assertValidStoreKey 直接可用（导出契约）', () => {
  assert.doesNotThrow(() => assertValidStoreKey('replay:a:1'));
  assert.throws(() => assertValidStoreKey('x'.repeat(513)));
});
