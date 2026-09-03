/**
 * chain-state-store.js — Smart Account 链上状态持久层
 *
 * Sprint 2.6 T2 建立（单文件全量 JSON）；Sprint 6 T3 重构为行级分片 + 可注入
 * store 后端（agent-sdk store-interface），修复多实例 last-write-wins 丢数据。
 *
 * Sprint 6 T3 语义（设计定稿见 Sprint6计划.md）：
 *   - 行级分片（不同行零竞争，同行按语义合并）：
 *       chain:meta                 → { chainUrl, profile }          write（LWW，匹配
 *                                                                    旧文件 guard 语义）
 *       state:account:<accountId>  → serializeEntry 输出            RMW union 合并
 *       sim:arm:<accountId>        → { digest, at }                 write（LWW 正确：
 *                                                                    安全性由 execute
 *                                                                    digest 匹配保证）
 *       ledger:tx:<txHash>         → { records: [...] }（生命周期） recordTx 写穿追加
 *   - 不变量冲突：owner/contractAddress/emergencyKey 创建后不可变——同 accountId
 *     两份不同配置 → STATE_CONFIG_CONFLICT 显式失败（fail-closed），绝不静默取一方。
 *   - RMW 合并规则：sessions 按 sessionId union；txHashes union + 环形 20；
 *     currentSessionId 非空覆盖（与单机 set 语义一致）。
 *   - recordTx 写穿（write-through）：广播事实即时入共享后端 → 跨实例可见
 *     （T4.2 对账去重的基础）。共享后端失败 → 传播（台账缺失会导致重复广播，
 *     不可静默）。
 *   - 后端解析：SMART_ACCOUNT_STATE_FILE 以 .sqlite/.db 结尾（或
 *     NEXUS_STORE_BACKEND=sqlite）→ sqlite 共享（多实例）；.json/缺省 → local 单机。
 *     显式 sqlite 构造失败 → 抛错（启动 fail-closed：状态丢失比不可用更危险）；
 *     local 损坏 → stderr 告警 + 自愈重建（fail-open 于启动、fail-closed 于交易，
 *     与 Sprint 2.6 语义一致）。
 *   - 旧 JSON 状态文件（顶层 accounts 数组）→ 启动一次性迁移入 store，原文件留 .bak。
 *
 * 对外 API 不变：loadChainState / saveChainState / recordTx / listTx /
 * recordBroadcast / serializeEntry / initTxLedger / getTxLedger。
 * 新增（Sprint 6 T3）：persistAccountRow / persistSimArm / getStateBackend。
 *
 * 纯内存模式（未设 SMART_ACCOUNT_STATE_FILE）：进程内台账/状态（向后兼容基线）。
 * conn（ethers Contract 运行时对象）永不落盘，恢复时由调用方重建。
 */
import {
  existsSync,
  readFileSync,
  copyFileSync,
  unlinkSync,
  renameSync,
} from 'node:fs';
import { createLocalStore, createSqliteStore } from 'aegis-agent-sdk';

const MAX_TX_HASHES_PER_ACCOUNT = 20;
const MAX_TX_RECORDS = 200;

const KEY_META = 'chain:meta';
const keyAccount = (accountId) => `state:account:${accountId}`;
const keySimArm = (accountId) => `sim:arm:${accountId}`;
const keyLedgerTx = (txHash) => `ledger:tx:${txHash}`;

/** 同 accountId 不允许漂移的不变量字段（创建后不可变）。 */
const INVARIANT_FIELDS = ['contractAddress', 'owner', 'emergencyKey'];

// ── 交易台账（进程内副本：查询快路径 + 纯内存模式的唯一载体） ─────────────
let txLedger = [];

// ── 后端解析（memoized；显式 sqlite 失败 fail-closed，local 损坏自愈） ─────
let stateBackend = null;

/** 读取状态文件路径（env 驱动；未设置返回 null → 纯内存模式）。 */
export function getChainStateFile() {
  return process.env.SMART_ACCOUNT_STATE_FILE || null;
}

/**
 * 是否为「共享多实例」后端（sqlite）——T4 relayer 非ce 协调/跨实例对账去重
 * 仅在共享后端启用时激活，避免单机/local/纯内存模式改变基线行为。
 * @returns {boolean}
 */
export function isSharedBackend() {
  const file = getChainStateFile();
  if (!file) return false; // 纯内存 → 单机
  if (process.env.NEXUS_STORE_BACKEND === 'sqlite') return true;
  return /\.(sqlite3?|db)$/i.test(file);
}

/**
 * 旧格式检测 + 迁移：SMART_ACCOUNT_STATE_FILE 指向 Sprint 2.6 全量 JSON
 * （顶层 accounts 数组）→ 迁入行级 store，原文件留 .bak。返回迁移负载或 null。
 *
 * #2 迁移幂等：若 .bak 已存在则假定迁移已执行（跳过 copyFileSync，避免反复覆
 * 盖丢失原始备份）；若原文件 unlink 失败（Windows 句柄锁）则 rename 为
 * `.legacy-migrated`——下次启动 existsSync(原文件)=false 不再重复走此路径。
 */
function tryMigrateLegacyJson(file) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return null; // 非 JSON 垃圾 → 走损坏自愈路径
  }
  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.accounts)) return null;
  const payload = {
    chainUrl: parsed.chainUrl ?? null,
    profile: parsed.profile ?? null,
    accounts: parsed.accounts,
    transactions: Array.isArray(parsed.transactions) ? parsed.transactions : [],
    simulations: Array.isArray(parsed.simulations) ? parsed.simulations : [],
  };
  const bak = `${file}.bak`;
  if (!existsSync(bak)) copyFileSync(file, bak); // 幂等：已存在 .bak 不覆盖（保留原始备份）
  try {
    unlinkSync(file);
  } catch {
    try {
      // Windows 句柄锁：rename 不受共享读锁影响（换路径后原 file 路径下次
      // existsSync=false，不再重复触发迁移）。.legacy-migrated 留作人工备查。
      renameSync(file, `${file}.legacy-migrated`);
    } catch {
      // 极端情况：rename 也失败（跨卷/权限）。返回 payload 仍会在本进程 seed
      // 到 store，下次启动会再次尝试——但 .bak 已经存在、不会丢原始备份，
      // 属于有限重试无数据丢失的低风险循环。
    }
  }
  return payload;
}

/**
 * 取共享/单机状态后端（memoized）。
 * - sqlite（显式或 .sqlite/.db 后缀）：构造失败直接抛错 → 调用方启动 fail-closed。
 * - local（.json/其他）：损坏 → 尝试旧格式迁移；仍是垃圾 → stderr 告警 +
 *   自愈重建空态（下次 persist 覆写），与 Sprint 2.6「启动 fail-open」一致。
 */
export function getStateBackend() {
  if (stateBackend) return stateBackend;
  const file = getChainStateFile();
  if (!file) {
    stateBackend = createLocalStore(); // 纯内存（无持久化语义）
    return stateBackend;
  }
  const explicitSqlite = process.env.NEXUS_STORE_BACKEND === 'sqlite';
  if (explicitSqlite || /\.(sqlite3?|db)$/i.test(file)) {
    stateBackend = createSqliteStore({ file }); // fail-closed：抛错由调用方处理
    return stateBackend;
  }
  try {
    // 先主动检测旧格式（Sprint 2.6 全量 JSON）——createLocalStore 对缺 entries
    // 键的合法 JSON 对象宽容（当空 store 加载），不能依赖它抛错触发迁移。
    const legacy = existsSync(file) ? tryMigrateLegacyJson(file) : null;
    if (legacy) {
      // 旧全量 JSON → 行级 store：一次性迁入（.bak 已保留），复用与在线路径
      // 相同的合并原语。
      stateBackend = createLocalStore({ file });
      seedFromLegacy(stateBackend, legacy);
      process.stderr.write(`[chain-state-store] migrated legacy full-state JSON to row-sharded store: ${file} (backup: ${file}.bak)\n`);
      return stateBackend;
    }
    stateBackend = createLocalStore({ file });
  } catch (err) {
    process.stderr.write(
      `[chain-state-store] WARNING: state file corrupted — starting with empty state (fail-open at startup, fail-closed at transactions, Sprint 2.6 semantics): ${err.message}\n`,
    );
    try {
      unlinkSync(file); // 自愈：移除损坏文件，下次 persist 重建（等价旧"覆写"行为）
      stateBackend = createLocalStore({ file });
    } catch {
      stateBackend = createLocalStore(); // 目录只读等 → 本会话纯内存
    }
  }
  return stateBackend;
}

/** 把旧全量状态迁入行级 store（迁移专用；复用与在线路径相同的合并原语）。 */
function seedFromLegacy(store, legacy) {
  if (legacy.chainUrl || legacy.profile) {
    store.write(KEY_META, { chainUrl: legacy.chainUrl, profile: legacy.profile });
  }
  for (const acc of legacy.accounts) {
    if (acc?.accountId) upsertAccountRow(store, acc);
  }
  for (const s of legacy.simulations) {
    if (s?.accountId) store.write(keySimArm(s.accountId), { digest: s.digest, at: s.at });
  }
  const byHash = new Map();
  for (const rec of legacy.transactions) {
    if (!rec?.txHash) continue;
    byHash.set(rec.txHash, [...(byHash.get(rec.txHash) || []), rec]);
  }
  for (const [hash, recs] of byHash) store.write(keyLedgerTx(hash), { txHash: hash, records: recs });
  store.evictOldest('ledger:tx:', MAX_TX_RECORDS);
}

// ── 行级写原语 ─────────────────────────────────────────────────────────────

function unionBySessionId(existing = [], incoming = []) {
  const byId = new Map();
  for (const s of existing) if (s?.sessionId) byId.set(s.sessionId, s);
  for (const s of incoming) if (s?.sessionId) byId.set(s.sessionId, s);
  return [...byId.values()];
}

function unionTail(existing = [], incoming = [], cap) {
  const merged = [...new Set([...existing, ...incoming])];
  return cap && merged.length > cap ? merged.slice(-cap) : merged;
}

/**
 * 台账生命周期去重：同 (txHash, status) 只保留最新 submittedAt 一条。
 * 链上事实：一个 txHash 只能被挖出一次——跨实例/跨重启的重复 confirmed
 * 记录是同一事实的冗余重放（at-least-once 写入 + 幂等存储）。完整审计流
 * 在 audit log，台账是可查询的生命周期事实集（submitted → confirmed/failed）。
 */
function dedupeLifecycleRecords(records) {
  const byStatus = new Map();
  for (const r of records) {
    const prev = byStatus.get(r.status);
    if (!prev || String(r.submittedAt) > String(prev.submittedAt)) byStatus.set(r.status, r);
  }
  return [...byStatus.values()].sort((a, b) => String(a.submittedAt).localeCompare(String(b.submittedAt)));
}

/**
 * 行级 upsert：新行插入 / 既有行 RMW union 合并。
 * 不变量字段（contractAddress/owner/emergencyKey）冲突 → STATE_CONFIG_CONFLICT
 * （fail-closed：同 accountId 两份不同配置 = 配置漂移，必须显式失败，绝不静默取一方）。
 */
function upsertAccountRow(store, serialized) {
  store.writeAtomically(keyAccount(serialized.accountId), (cur) => {
    if (!cur) {
      // #1 单轨化：行级不再存 chainUrl/profile，KEY_META 独占 chain-env 单例
      // 语义。逐行携带这些字段是双轨漂移的根源。
      const { chainUrl: _cu, profile: _pu, ...rest } = serialized; // eslint-disable-line no-unused-vars
      return { ...rest };
    }
    for (const f of INVARIANT_FIELDS) {
      if (cur[f] != null && serialized[f] != null && String(cur[f]) !== String(serialized[f])) {
        const err = new Error(
          `state config conflict on account '${serialized.accountId}': invariant field '${f}' stored='${cur[f]}' incoming='${serialized[f]}' — same accountId must not be re-registered with different invariants (fail-closed, audit the .bak/ledger to reconcile)`,
        );
        err.code = 'STATE_CONFIG_CONFLICT';
        throw err;
      }
    }
    return {
      ...cur,
      currentSessionId: serialized.currentSessionId || cur.currentSessionId,
      sessions: unionBySessionId(cur.sessions, serialized.sessions),
      txHashes: unionTail(cur.txHashes, serialized.txHashes, MAX_TX_HASHES_PER_ACCOUNT),
    };
  });
  // #1：chainUrl/profile 统一从 KEY_META 维护；传入 account 携带的值若非空
  // 则合并到单例（LWW 与旧全量文件保存语义一致）。不同 account 携带不同值
  // 时 LWW 自然胜出——同一 store 只允许被 chain-env guard 认作一条链，这正
  // 是单例语义的本意。
  if (serialized.chainUrl || serialized.profile) {
    store.write(KEY_META, { chainUrl: serialized.chainUrl ?? null, profile: serialized.profile ?? null });
  }
}

/** 序列化一个 entry 的可持久字段（剥离 conn 等运行时对象）。 */
export function serializeEntry(entry) {
  return {
    accountId: entry.accountId,
    contractAddress: entry.contractAddress,
    owner: entry.owner,
    emergencyKey: entry.emergencyKey,
    chainUrl: entry.chainUrl,
    profile: entry.profile || null,
    currentSessionId: entry.currentSessionId || null,
    txHashes: Array.isArray(entry.txHashes) ? entry.txHashes : [],
    sessions: Array.from((entry.sessions || new Map()).values()).map((s) => ({
      sessionId: s.sessionId,
      agentId: s.agentId,
      agentEvmAddress: s.agentEvmAddress,
      issuedAt: s.issuedAt,
      expiresAt: s.expiresAt,
      maxPerTx: String(s.maxPerTx ?? ''),
      maxDaily: String(s.maxDaily ?? ''),
      whitelist: {
        allowedChains: s.whitelist?.allowedChains ?? [],
        allowedAssets: s.whitelist?.allowedAssets ?? [],
        allowedContracts: s.whitelist?.allowedContracts ?? [],
        allowedMethods: s.whitelist?.allowedMethods ?? [],
        allowedRecipients: s.whitelist?.allowedRecipients ?? [],
      },
    })),
  };
}

/**
 * Sprint 6 T3.2 — 按行持久化单个账户（替代全量 saveChainState 的 server 侧路径）。
 * 纯内存模式 no-op。共享后端失败 → 传播（fail-closed）。
 * @param {object} entry 内存 entry（smartAccounts Map 的值）
 */
export function persistAccountRow(entry) {
  if (!getChainStateFile() || !entry?.accountId) return;
  upsertAccountRow(getStateBackend(), serializeEntry(entry));
}

/**
 * Sprint 6 T3.1 — arm 写穿共享后端（LWW：最新 preview 意图覆盖是正确语义，
 * execute 安全性由 digest 精确匹配保证，与写入顺序无关）。
 * 纯内存模式 no-op。共享后端失败 → 传播（视为未 arm，调用方 fail-closed）。
 */
export function persistSimArm(accountId, { digest, at }) {
  if (!getChainStateFile() || !accountId) return;
  getStateBackend().write(keySimArm(accountId), { digest, at });
}

// ── 全量读写（兼容 API：签名/行为对既有调用方不变，内部按行合并） ─────────

/**
 * 全量加载持久状态（行级读出，返回形状与 Sprint 2.6 相同）。
 * @returns {{ chainUrl: string|null, profile: string|null, accounts: object[], transactions: object[], simulations: object[] }}
 */
export function loadChainState() {
  const file = getChainStateFile();
  if (!file) {
    return { chainUrl: null, profile: null, accounts: [], transactions: [], simulations: [] };
  }
  const store = getStateBackend(); // sqlite 显式失败 → 抛错（启动 fail-closed）
  const meta = store.read(KEY_META) || {};
  const accountRows = store.list('state:account:');
  const accounts = Object.keys(accountRows).map((k) => accountRows[k]);
  const simRows = store.list('sim:arm:');
  const simulations = Object.keys(simRows).map((k) => ({
    accountId: k.slice('sim:arm:'.length),
    digest: simRows[k].digest,
    at: simRows[k].at,
  }));
  const ledgerRows = store.list('ledger:tx:');
  const transactions = Object.keys(ledgerRows)
    .flatMap((k) => dedupeLifecycleRecords(ledgerRows[k].records || []))
    .sort((a, b) => String(a.submittedAt).localeCompare(String(b.submittedAt)))
    .slice(-MAX_TX_RECORDS);
  return {
    chainUrl: meta.chainUrl ?? null,
    profile: meta.profile ?? null,
    accounts,
    transactions,
    simulations,
  };
}

/**
 * 全量保存（兼容 API；内部按行合并——accounts RMW union、sim LWW、台账按
 * txHash 行覆写，绝不整体覆盖丢行）。纯内存模式 no-op。
 */
export function saveChainState({ chainUrl, profile, accounts = [], transactions = [], simulations = [] } = {}) {
  if (!getChainStateFile()) return; // 纯内存模式：不落盘
  const store = getStateBackend();
  if (chainUrl || profile) store.write(KEY_META, { chainUrl: chainUrl ?? null, profile: profile ?? null });
  for (const acc of accounts) {
    if (acc?.accountId) upsertAccountRow(store, acc);
  }
  for (const s of simulations) {
    if (s?.accountId) store.write(keySimArm(s.accountId), { digest: s.digest, at: s.at });
  }
  const byHash = new Map();
  for (const rec of transactions) {
    if (!rec?.txHash) continue;
    byHash.set(rec.txHash, [...(byHash.get(rec.txHash) || []), rec]);
  }
  for (const [hash, recs] of byHash) store.write(keyLedgerTx(hash), { txHash: hash, records: recs });
  store.evictOldest('ledger:tx:', MAX_TX_RECORDS);
}

/**
 * 记录一次广播 txHash（per account 环形保留，避免无限增长）。
 * @param {object} entry 内存 entry（会原地更新 txHashes）
 * @param {string} txHash
 */
export function recordBroadcast(entry, txHash) {
  if (!txHash) return;
  if (!Array.isArray(entry.txHashes)) entry.txHashes = [];
  entry.txHashes.push(txHash);
  if (entry.txHashes.length > MAX_TX_HASHES_PER_ACCOUNT) {
    entry.txHashes = entry.txHashes.slice(-MAX_TX_HASHES_PER_ACCOUNT);
  }
}

// ── 交易台账 API (Sprint 2.7 T3 + Sprint 6 T3.3 写穿) ──────────────────────

/** 从落盘状态初始化进程内台账（重启恢复；纯内存模式传入空态）。 */
export function initTxLedger(state) {
  txLedger = Array.isArray(state?.transactions) ? state.transactions : [];
}

/**
 * 记录一笔交易生命周期事实。
 * Sprint 6 T3.3：设状态文件时写穿共享后端（跨实例立即可见——T4.2 对账去重
 * 的依据）；共享后端失败 → 传播（台账静默缺失会导致重复广播决策，不可吞）。
 * 纯内存模式：仅进程内台账（基线行为）。
 * @param {object} rec { txHash, accountId, sessionId, status, errorName?, blockNumber?, gasUsed?, submittedAt, ... }
 */
export function recordTx(rec) {
  if (!rec || !rec.txHash) return null;
  txLedger.push(rec);
  if (txLedger.length > MAX_TX_RECORDS) {
    txLedger = txLedger.slice(-MAX_TX_RECORDS);
  }
  if (getChainStateFile()) {
    const store = getStateBackend();
    store.writeAtomically(keyLedgerTx(rec.txHash), (cur) => ({
      txHash: rec.txHash,
      records: [...(Array.isArray(cur?.records) ? cur.records : []), rec],
    }));
    store.evictOldest('ledger:tx:', MAX_TX_RECORDS);
  }
  return rec;
}

/** 当前进程内台账全量（兼容保留；与 listTx 语义一致：store 模式查 store，
 *  mem 模式查进程内数组——避免对外导出 API 与跨实例事实集不一致。） */
export function getTxLedger() {
  if (getChainStateFile()) return listTx({ limit: MAX_TX_RECORDS });
  return txLedger;
}

/**
 * 查询交易台账。
 * Sprint 6 T3.3：设状态文件时查 store（跨实例可见：别的实例广播的事实本
 * 实例也能查到）；纯内存模式查进程内数组（基线行为）。
 * @param {object} [opts]
 * @param {string} [opts.txHash] 精确匹配一笔交易
 * @param {string} [opts.accountId] 按账户过滤
 * @param {number} [opts.limit=50] 最多返回条数
 */
export function listTx({ txHash, accountId, limit = 50 } = {}) {
  let rows;
  if (!getChainStateFile()) {
    // 纯内存模式：进程内台账（基线行为）。
    rows = txLedger;
    if (txHash) rows = rows.filter((r) => r.txHash === txHash);
  } else {
    // store 路径：跨实例可见（本实例与其他实例广播的事实都在）。
    const store = getStateBackend();
    if (txHash) {
      rows = dedupeLifecycleRecords(store.read(keyLedgerTx(txHash))?.records || []);
    } else {
      rows = Object.values(store.list('ledger:tx:'))
        .flatMap((r) => dedupeLifecycleRecords(r.records || []))
        .sort((a, b) => String(a.submittedAt).localeCompare(String(b.submittedAt)));
    }
  }
  if (accountId) rows = rows.filter((r) => r.accountId === accountId);
  return rows.slice(-limit);
}

/** 测试隔离：清空台账 + 关闭后端（下次访问按当前 env 重建）。 */
export function __resetTxLedgerForTest() {
  txLedger = [];
  if (stateBackend) {
    try { stateBackend.close(); } catch { /* already closed */ }
    stateBackend = null;
  }
}
