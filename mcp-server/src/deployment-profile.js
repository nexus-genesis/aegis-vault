/**
 * deployment-profile.js — Sprint 7 T2: Deployment profile 封装
 *
 * 把散落的环境变量封装成「三档内建 profile + 可选外部 profile 文件」，做 schema
 * 校验（含 fail-closed），并（可选）把 profile 内的 env 写回 process.env —— 使
 * 下游 `chain-config.js` / `chain-state-store.js` / metrics / health 的现有 env
 * 读取逻辑完全不用改。
 *
 * 设计约束（Sprint 7 关键约束 1/3/4）：
 *   - 默认关 / 可选 SPI：未设置 NEXUS_PROFILE_FILE → 不做任何事，行为与基线逐字
 *     节一致（不隐式引入依赖，不覆盖任何已有 env）。
 *   - fail-closed：profile 文件缺必填项 / 含未知字段（严格模式）/ 语法错误 →
 *     抛带 `code` 的错（复用 chain-config 的 fail 模式）。
 *   - 密钥最少接触面：profile 文件可含密钥 env 键（如 CHAIN_OWNER_PK），但本
 *     模块绝不把值打日志、绝不进 MCP 参数。读取仅注入 process.env。
 *   - dry-run：NEXUS_PROFILE_DRY_RUN=1 → 只加载+校验，不写 process.env（发布前
 *     preflight 复用）。返回校验结果供 T4 使用。
 *
 * 文件格式：
 *   - `.env`      每行 `KEY=value`（# 注释，空行忽略，值可带引号）。
 *   - `.json`     `{ "profile": "production", "env": { KEY: value } }`
 *                 env 内键必须全大写（与进程 env 约定一致）。
 */
import { readFileSync, existsSync } from 'node:fs';

/**
 * 三档内建 profile 的必填项约束。仅当 NEXUS_PROFILE_FILE 省略 profile 字段时，
 * 依此为其补默认必填扫描；显式 profile 文件已自带 profile+env，无需内建表。
 * @type {Record<string, string[]>}
 */
export const PROFILE_REQUIRED = {
  local: [],
  testnet: ['CHAIN_RPC_URL', 'CHAIN_RELAYER_PK'],
  production: ['CHAIN_RPC_URL', 'CHAIN_OWNER_PK', 'CHAIN_EMERGENCY_PK', 'CHAIN_RELAYER_PK'],
};

/** profile 取值合法集合。 */
export const PROFILE_NAMES = ['local', 'testnet', 'production'];

/**
 * 解析并校验一段 .env 文本为 { KEY: value }。
 * @param {string} text
 * @returns {Record<string,string>}
 */
export function parseDotEnv(text) {
  const out = {};
  for (let line of text.split(/\r?\n/)) {
    line = line.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    let key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    // 去掉配对引号。
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (key) out[key] = value;
  }
  return out;
}

/**
 * 从 NEXUS_PROFILE_FILE 读入 profile 定义。
 * @param {string} file
 * @returns {{ profile: string, env: Record<string,string> }}
 */
export function parseProfileFile(file) {
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    const e = new Error(`NEXUS_PROFILE_FILE unreadable: ${file} (${err.message})`);
    e.code = 'NEXUS_PROFILE_UNREADABLE';
    throw e;
  }
  const lower = file.toLowerCase();
  if (lower.endsWith('.json')) {
    let obj;
    try {
      obj = JSON.parse(text);
    } catch {
      const e = new Error(`NEXUS_PROFILE_FILE invalid JSON: ${file}`);
      e.code = 'NEXUS_PROFILE_INVALID_JSON';
      throw e;
    }
    const env = obj?.env ?? {};
    const unknown = Object.keys(env).filter((k) => k.toUpperCase() !== k);
    if (unknown.length) {
      const e = new Error(
        `NEXUS_PROFILE_FILE env keys must be UPPERCASE (got: ${unknown.join(', ')}).`,
      );
      e.code = 'NEXUS_PROFILE_ENV_KEY_CASE';
      throw e;
    }
    return { profile: obj?.profile ?? null, env };
  }
  // 默认视为 .env
  return { profile: null, env: parseDotEnv(text) };
}

/**
 * 校验 profile 是否满足必填约束（缺 → fail-closed）。
 * @param {string} profile
 * @param {Record<string,string|undefined>} env
 */
export function assertRequired(profile, env) {
  const required = PROFILE_REQUIRED[profile] ?? [];
  const missing = required.filter((k) => !env[k]);
  if (missing.length) {
    const e = new Error(
      `NEXUS_PROFILE missing required env keys for CHAIN_PROFILE=${profile}: ${missing.join(', ')}.`,
    );
    e.code = 'NEXUS_PROFILE_MISSING_REQUIRED';
    throw e;
  }
}

/**
 * 加载 Deployment profile（幂等）。有副作用：默认会把 profile env 注入 process.env
 * （除非 dry-run），使下游 env 读取零改动。
 *
 * @param {object} [opts]
 * @param {boolean} [opts.dryRun] 仅校验不注入（缺省读 NEXUS_PROFILE_DRY_RUN）
 * @param {boolean} [opts.forceReload] 忽略已加载缓存（测试用）
 * @returns {{ loaded: boolean, profile: string|null, env: Record<string,string>, dryRun: boolean, missing: string[] }}
 */
let loadedCache = null;
export function loadDeploymentProfile({ dryRun, forceReload } = {}) {
  if (loadedCache && !forceReload) return loadedCache;
  const file = (process.env.NEXUS_PROFILE_FILE || '').trim();
  const isDry = dryRun ?? process.env.NEXUS_PROFILE_DRY_RUN === '1';
  const result = {
    loaded: false,
    profile: null,
    env: null,
    dryRun: isDry,
    missing: [],
    file: file || null,
  };
  if (!file) {
    loadedCache = result;
    return result;
  }
  if (!existsSync(file)) {
    const e = new Error(`NEXUS_PROFILE_FILE not found: ${file}`);
    e.code = 'NEXUS_PROFILE_NOT_FOUND';
    throw e;
  }
  const parsed = parseProfileFile(file);
  // profile 显式文件可用内建 profile 名，也可留空（此时各 env 键自身即表达意图）。
  const profile = parsed.profile ? String(parsed.profile).toLowerCase() : null;
  if (profile && !PROFILE_NAMES.includes(profile)) {
    const e = new Error(
      `NEXUS_PROFILE_FILE profiles invalid CHAIN_PROFILE "${profile}". Must be one of: ${PROFILE_NAMES.join(' / ')}.`,
    );
    e.code = 'NEXUS_PROFILE_INVALID_PROFILE';
    throw e;
  }
  // fail-closed：缺必填 → 抛错（无论 dry-run，preflight 就是要发现这个）。
  assertRequired(profile || process.env.CHAIN_PROFILE || 'local', {
    ...process.env,
    ...parsed.env,
  });
  result.profile = profile;
  result.env = parsed.env;
  result.loaded = true;
  if (parsed.env && parsed.env.CHAIN_PROFILE) {
    assertRequired(String(parsed.env.CHAIN_PROFILE).toLowerCase(), { ...process.env, ...parsed.env });
  }
  if (!isDry) {
    for (const [k, v] of Object.entries(parsed.env)) {
      // 只在当前未显式设置时注入 —— 显式 env 优先级最高（profile 是默认层）。
      if (process.env[k] === undefined) process.env[k] = v;
    }
    // 显式 profile 名 → 同步 CHAIN_PROFILE（供 chain-config 读取）。
    if (profile && process.env.CHAIN_PROFILE === undefined) process.env.CHAIN_PROFILE = profile;
  }
  loadedCache = result;
  return result;
}

/** 测试隔离。 */
export function __resetProfileForTest() {
  loadedCache = null;
}