/**
 * store-interface.js — Sprint 6 T1 共享状态抽象（可注入后端）
 *
 * 统一接口（所有后端同构，T2-T4 消费方无差别）：
 *   read(key)                          → value | null
 *   write(key, value)                  → { version }                 覆盖写（版本+1）
 *   claim(key, value)                  → { claimed }                 恰好一次原子登记（全族首个成功）
 *   writeAtomically(key, mutate, opts) → { value, version }          原子 read-modify-write（CAS 重试）
 *   has(key) / keys(prefix) / list(prefix)
 *   purgeExpired(beforeTs)             → { purged }                  按 updated_at 清理（replay 窗口）
 *   delete(key)                        → { deleted }
 *   instanceId() / instanceFamilyId()  — 审计对账（谁改了什么 / 哪些实例共享同一状态）
 *   close()
 *
 * 后端：
 *   - local  ：进程内 Map + 本地 JSON（tmp+rename 原子写，启动恢复）。单实例语义，
 *              与现基线行为一致——默认后端，零依赖，Node 18+ 全兼容。
 *   - sqlite ：node:sqlite 单文件 WAL（Node 22.5+ 实验性内置）。多进程可开同一文件；
 *              claim 用 INSERT ... ON CONFLICT DO NOTHING（changes=1 即全族恰好一次）；
 *              writeAtomically 用 BEGIN IMMEDIATE 事务 + 版本 CAS。运行时探测，
 *              不可用（低版本 Node）→ 构造抛错（fail-closed，绝不静默降级 local）。
 *   - redis  ：SPI 契约占位——本 Sprint 不实现、不引入依赖，仅定义接口供后续接入。
 *
 * Fail-closed 原则（Sprint 6 规划约束 #1/#2）：
 *   构造时文件损坏/路径不可写/后端不可用 → 抛错拒绝启用；
 *   不静默回退空态或各自独立窗口放低安全。降级决策由调用方显式做出并告警。
 *
 * key 约定：`<schema>:<name>`（如 `replay:sender:nonce` / `sim:digest` / `state:accountId`）。
 * value 为任意可 JSON 序列化对象。
 */

import { existsSync, readFileSync, writeFileSync, renameSync, mkdirSync, unlinkSync } from 'node:fs';
import { dirname, resolve as resolvePath } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

/**
 * node:sqlite / Node >= 22.5 能力探测（共享 backen 的运行时门槛）。
 *
 * 供测试在低版本 Node 下对 sqlite 专属用例做显式 skip（保留矩阵 18/20 腿校验
 * 非 sqlite 面）；运行时本身仍 fail-closed——createSqliteStore 不因本旗标改变
 * 拒绝语义，探测仅用于上层（测试/协调器）决定是否走共享路径。
 */
export const sqliteAvailable = (() => {
  try { require('node:sqlite'); return true; } catch { return false; }
})();

/** key 校验：非空字符串、≤512 字符（schema:name 约定由调用方保证）。 */
export function assertValidStoreKey(key) {
  if (typeof key !== 'string' || key.length === 0 || key.length > 512) {
    throw new Error(`invalid store key: ${JSON.stringify(key)}`);
  }
}

function assertValidValue(value) {
  // undefined 无法 JSON 序列化（会丢字段）——拒绝而非静默损坏。
  const s = JSON.stringify(value);
  if (s === undefined) throw new Error('store value must be JSON-serializable');
}

// ── local 后端（默认；单实例语义） ─────────────────────────────────────────

/**
 * 进程内 Map + 本地 JSON 持久化（可选）。
 * @param {object} [options]
 * @param {string|null} [options.file] 持久化 JSON 路径；null → 纯内存。
 *        file 损坏 → 构造抛错（fail-closed；调用方决定是否显式降级重建）。
 */
export function createLocalStore({ file = null } = {}) {
  const absFile = file ? resolvePath(file) : null;
  const map = new Map(); // key -> { value, version, updatedAt }
  const instance = `local-${process.pid}-${randomUUID().slice(0, 8)}`;

  if (absFile && existsSync(absFile)) {
    let raw;
    try {
      raw = JSON.parse(readFileSync(absFile, 'utf8'));
    } catch (err) {
      throw new Error(`local store file corrupted (fail-closed): ${absFile}: ${err.message}`);
    }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new Error(`local store file corrupted (fail-closed): ${absFile}: not an object`);
    }
    for (const [k, rec] of Object.entries(raw.entries || {})) {
      if (rec && typeof rec === 'object' && 'value' in rec && Number.isInteger(rec.version)) {
        map.set(k, { value: rec.value, version: rec.version, updatedAt: rec.updatedAt ?? 0 });
      }
    }
  }

  function persist() {
    if (!absFile) return;
    const entries = {};
    for (const [k, rec] of map.entries()) entries[k] = rec;
    const payload = JSON.stringify({ family: absFile, entries, savedAt: new Date().toISOString() }, null, 2);
    mkdirSync(dirname(absFile), { recursive: true });
    const tmp = `${absFile}.tmp`;
    writeFileSync(tmp, payload, 'utf8');
    try {
      renameSync(tmp, absFile); // POSIX 原子；Windows 对已存在目标 rename 会失败 → 退化覆盖写
    } catch {
      writeFileSync(absFile, payload, 'utf8');
      if (existsSync(tmp)) unlinkSync(tmp);
    }
  }

  return {
    type: 'local',
    instanceId: () => instance,
    instanceFamilyId: () => (absFile ? `file:${absFile}` : `memory:${instance}`),

    read(key) {
      assertValidStoreKey(key);
      const rec = map.get(key);
      return rec ? structuredClone(rec.value) : null;
    },
    has(key) {
      assertValidStoreKey(key);
      return map.has(key);
    },
    // 单进程同步段内天然原子：首个 claim 成功，其余 claimed:false。
    claim(key, value) {
      assertValidStoreKey(key);
      assertValidValue(value);
      if (map.has(key)) return { claimed: false };
      map.set(key, { value, version: 1, updatedAt: Date.now() });
      persist();
      return { claimed: true };
    },
    write(key, value) {
      assertValidStoreKey(key);
      assertValidValue(value);
      const prev = map.get(key);
      const version = (prev?.version ?? 0) + 1;
      map.set(key, { value, version, updatedAt: Date.now() });
      persist();
      return { version };
    },
    // 进程内原子（无并发窗口）；expectedVersion 提供时校验（语义与 sqlite 对齐）。
    writeAtomically(key, mutate, { expectedVersion } = {}) {
      assertValidStoreKey(key);
      if (typeof mutate !== 'function') throw new Error('writeAtomically requires a mutate function');
      const rec = map.get(key);
      const currentVersion = rec?.version ?? 0;
      if (expectedVersion !== undefined && expectedVersion !== currentVersion) {
        const err = new Error(`CAS conflict on ${key}: expected v${expectedVersion}, found v${currentVersion}`);
        err.code = 'STORE_CAS_CONFLICT';
        throw err;
      }
      const next = mutate(rec ? structuredClone(rec.value) : null);
      assertValidValue(next);
      const version = currentVersion + 1;
      map.set(key, { value: next, version, updatedAt: Date.now() });
      persist();
      return { value: structuredClone(next), version };
    },
    delete(key) {
      assertValidStoreKey(key);
      const deleted = map.delete(key);
      if (deleted) persist();
      return { deleted };
    },
    keys(prefix = '') {
      return [...map.keys()].filter((k) => k.startsWith(prefix)).sort();
    },
    list(prefix = '') {
      const out = {};
      for (const k of this.keys(prefix)) out[k] = structuredClone(map.get(k).value);
      return out;
    },
    purgeExpired(beforeTs) {
      let purged = 0;
      for (const [k, rec] of [...map.entries()]) {
        if (rec.updatedAt < beforeTs) { map.delete(k); purged += 1; }
      }
      if (purged > 0) persist();
      return { purged };
    },
    // 容量硬上限：按插入序（Map 迭代序）FIFO 淘汰最旧 prefix 条目至 keepMax。
    evictOldest(prefix = '', keepMax = 0) {
      const matching = [...map.keys()].filter((k) => k.startsWith(prefix));
      const excess = matching.length - keepMax;
      if (excess <= 0) return { evicted: 0 };
      for (const k of matching.slice(0, excess)) map.delete(k);
      persist();
      return { evicted: excess };
    },
    close() { persist(); },
  };
}

// ── sqlite 后端（共享默认；Node 22.5+ node:sqlite） ────────────────────────

/**
 * 单文件 WAL 共享后端。多实例（多进程/同进程多连接）可开同一文件：
 * claim 恰好一次、writeAtomically 事务+版本 CAS、busy_timeout 串行化写竞争。
 * @param {object} options
 * @param {string} options.file sqlite 文件路径（':memory:' 仅测试用——非共享）。
 *        打开/建表失败、node:sqlite 不可用 → 构造抛错（fail-closed，不静默降级）。
 */
export function createSqliteStore({ file } = {}) {
  if (!file) throw new Error('createSqliteStore requires { file } (fail-closed)');
  let DatabaseSync;
  try {
    ({ DatabaseSync } = require('node:sqlite'));
  } catch {
    throw new Error(
      'sqlite store backend requires node:sqlite (Node >= 22.5). ' +
      'Current runtime does not provide it — refusing to silently degrade to a local backend (fail-closed).',
    );
  }

  const absFile = file === ':memory:' ? ':memory:' : resolvePath(file);

  let db;
  try {
    if (absFile !== ':memory:') mkdirSync(dirname(absFile), { recursive: true });
    db = new DatabaseSync(absFile);
    db.exec('PRAGMA journal_mode = WAL');
    db.exec('PRAGMA busy_timeout = 5000');
    db.exec('PRAGMA synchronous = NORMAL');
    db.exec(`
      CREATE TABLE IF NOT EXISTS store_kv (
        store_key  TEXT PRIMARY KEY,
        value      TEXT NOT NULL,
        version    INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        instance   TEXT NOT NULL
      )
    `);
  } catch (err) {
    try { db?.close(); } catch { /* already closed */ }
    throw new Error(`sqlite store open failed (fail-closed): ${absFile}: ${err.message}`);
  }

  const instance = `sqlite-${process.pid}-${randomUUID().slice(0, 8)}`;
  const stmtRead = db.prepare('SELECT value, version FROM store_kv WHERE store_key = ?');
  const stmtInsertIgnore = db.prepare(`
    INSERT INTO store_kv (store_key, value, version, updated_at, instance)
    VALUES (?, ?, 1, ?, ?)
    ON CONFLICT (store_key) DO NOTHING
  `);
  const stmtUpsert = db.prepare(`
    INSERT INTO store_kv (store_key, value, version, updated_at, instance)
    VALUES (?, ?, 1, ?, ?)
    ON CONFLICT (store_key) DO UPDATE SET
      value = excluded.value,
      version = store_kv.version + 1,
      updated_at = excluded.updated_at,
      instance = excluded.instance
  `);
  const stmtCasUpdate = db.prepare(
    'UPDATE store_kv SET value = ?, version = version + 1, updated_at = ?, instance = ? WHERE store_key = ? AND version = ?',
  );
  const stmtKeys = db.prepare('SELECT store_key FROM store_kv WHERE substr(store_key, 1, ?) = ? ORDER BY store_key');
  const stmtList = db.prepare('SELECT store_key, value FROM store_kv WHERE substr(store_key, 1, ?) = ? ORDER BY store_key');
  const stmtDelete = db.prepare('DELETE FROM store_kv WHERE store_key = ?');
  const stmtPurge = db.prepare('DELETE FROM store_kv WHERE updated_at < ?');
  const stmtCountPrefix = db.prepare('SELECT COUNT(*) AS n FROM store_kv WHERE substr(store_key, 1, ?) = ?');
  const stmtEvictOldest = db.prepare(`
    DELETE FROM store_kv
    WHERE store_key IN (
      SELECT store_key FROM store_kv
      WHERE substr(store_key, 1, ?) = ?
      ORDER BY updated_at ASC, rowid ASC
      LIMIT ?
    )
  `);

  function parseRowValue(row) {
    return row ? JSON.parse(row.value) : null;
  }

  return {
    type: 'sqlite',
    instanceId: () => instance,
    instanceFamilyId: () => `sqlite:${absFile}`,

    read(key) {
      assertValidStoreKey(key);
      const row = stmtRead.get(key);
      return row ? parseRowValue(row) : null;
    },
    has(key) {
      assertValidStoreKey(key);
      return stmtRead.get(key) !== undefined;
    },
    // INSERT ... ON CONFLICT DO NOTHING：changes=1 ⇔ 本调用是全族首个登记者。
    claim(key, value) {
      assertValidStoreKey(key);
      assertValidValue(value);
      const res = stmtInsertIgnore.run(key, JSON.stringify(value), Date.now(), instance);
      return { claimed: res.changes === 1 };
    },
    write(key, value) {
      assertValidStoreKey(key);
      assertValidValue(value);
      const res = stmtUpsert.run(key, JSON.stringify(value), Date.now(), instance);
      // UPSERT 无返回版本——读回（同连接内已见自己的写）。
      const row = stmtRead.get(key);
      return { version: row.version };
    },
    /**
     * 原子 read-modify-write：BEGIN IMMEDIATE 事务内读版本 → mutate → 条件更新。
     * 并发更新同一 key → CAS 重试（默认 25 次）；expectedVersion 显式提供且不匹配 →
     * 抛 STORE_CAS_CONFLICT（调用方裁决，不自动重试——外部版本假设被打破）。
     */
    writeAtomically(key, mutate, { expectedVersion, retries = 25 } = {}) {
      assertValidStoreKey(key);
      if (typeof mutate !== 'function') throw new Error('writeAtomically requires a mutate function');
      let lastErr = null;
      for (let attempt = 0; attempt <= retries; attempt += 1) {
        try {
          db.exec('BEGIN IMMEDIATE');
          const row = stmtRead.get(key);
          const currentVersion = row ? row.version : 0;
          if (expectedVersion !== undefined && expectedVersion !== currentVersion) {
            db.exec('ROLLBACK');
            const err = new Error(`CAS conflict on ${key}: expected v${expectedVersion}, found v${currentVersion}`);
            err.code = 'STORE_CAS_CONFLICT';
            throw err;
          }
          let next;
          try {
            next = mutate(row ? parseRowValue(row) : null);
            assertValidValue(next);
          } catch (mutateErr) {
            // mutate 抛出的业务错误（如 STATE_CONFIG_CONFLICT）不属 CAS 竞争——
            // 回滚后直接传播，绝不进入重试循环（重试同样的业务冲突只会空转 25 次）。
            mutateErr.__mutateError = true;
            try { db.exec('ROLLBACK'); } catch { /* not in txn */ }
            throw mutateErr;
          }
          const serialized = JSON.stringify(next);
          let changes;
          if (row) {
            changes = stmtCasUpdate.run(serialized, Date.now(), instance, key, currentVersion).changes;
          } else {
            changes = stmtInsertIgnore.run(key, serialized, Date.now(), instance).changes;
          }
          if (changes !== 1) {
            db.exec('ROLLBACK'); // 行在事务内被外部连接抢先改写（WAL 下并发读快照）→ 重试
            lastErr = new Error(`CAS retry on ${key}`);
            continue;
          }
          db.exec('COMMIT');
          return { value: next, version: currentVersion + 1 };
        } catch (err) {
          if (err.code === 'STORE_CAS_CONFLICT') throw err;
          if (err.__mutateError) throw err; // mutate 业务错误：重试无意义，直接传播
          // 仅竞争类错误（BUSY/LOCKED）重试；其余（IO/序列化/编程错误）直接抛。
          if (!/BUSY|LOCKED/i.test(String(err.code || err.message))) throw err;
          try { db.exec('ROLLBACK'); } catch { /* not in txn */ }
          lastErr = err;
        }
      }
      throw new Error(`writeAtomically exhausted retries on ${key}: ${lastErr?.message}`);
    },
    delete(key) {
      assertValidStoreKey(key);
      return { deleted: stmtDelete.run(key).changes === 1 };
    },
    keys(prefix = '') {
      return stmtKeys.all(prefix.length, prefix).map((r) => r.store_key);
    },
    list(prefix = '') {
      const out = {};
      for (const row of stmtList.all(prefix.length, prefix)) out[row.store_key] = JSON.parse(row.value);
      return out;
    },
    purgeExpired(beforeTs) {
      return { purged: stmtPurge.run(beforeTs).changes };
    },
    // 容量硬上限：按 updated_at（claim/write 时间）最旧优先淘汰 prefix 条目至 keepMax。
    evictOldest(prefix = '', keepMax = 0) {
      const n = stmtCountPrefix.get(prefix.length, prefix).n;
      const excess = n - keepMax;
      if (excess <= 0) return { evicted: 0 };
      return { evicted: stmtEvictOldest.run(prefix.length, prefix, excess).changes };
    },
    close() { db.close(); },
  };
}

// ── redis 后端（SPI 契约占位——本 Sprint 不实现） ─────────────────────────

/**
 * Redis 后端契约（集中式共享、跨节点）。Sprint 6 明确不实现、不引入 ioredis 依赖：
 * 仅固化接口形状（与 local/sqlite 同构），供 Sprint 8+ 集中式 anti-replay 接入。
 * 现调用 → 抛 NotImplemented（fail-closed，防误用空壳）。
 */
export function createRedisStore() {
  throw new Error(
    'createRedisStore is a documented SPI placeholder (RFC P3 centralized anti-replay). ' +
    'Not implemented in Sprint 6 — use createLocalStore or createSqliteStore.',
  );
}

// ── 后端选择解析 ───────────────────────────────────────────────────────────

/**
 * 解析状态后端。
 * @param {object} options
 * @param {'auto'|'local'|'sqlite'} [options.backend='auto']
 * @param {string|null} [options.file] 状态文件路径。
 *   auto 规则：file 以 .sqlite/.db 结尾 → sqlite（共享）；其他 file → local(JSON)；无 file → local(纯内存)。
 *   显式 'sqlite'/'local' 按字面启用（sqlite 仍需 file，缺失即抛错）。
 *   env NEXUS_STORE_BACKEND / NEXUS_SHARED_STATE_FILE 作为 options 缺省时的回退来源。
 */
export function resolveStateBackend({ backend = 'auto', file = null } = {}) {
  const envBackend = process.env.NEXUS_STORE_BACKEND;
  const envFile = process.env.NEXUS_SHARED_STATE_FILE || null;
  const kind = backend !== 'auto' ? backend : (envBackend || 'auto');
  const theFile = file || envFile;

  if (kind === 'sqlite') {
    if (!theFile) throw new Error('sqlite backend requires a file (NEXUS_SHARED_STATE_FILE or options.file)');
    return createSqliteStore({ file: theFile });
  }
  if (kind === 'local') return createLocalStore({ file: theFile });
  // auto：按扩展名分流——共享后端必须是显式的（.sqlite/.db），否则保持单机默认。
  if (theFile && /\.(sqlite3?|db)$/i.test(theFile)) return createSqliteStore({ file: theFile });
  return createLocalStore({ file: theFile });
}
