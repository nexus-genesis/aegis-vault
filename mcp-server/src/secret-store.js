/**
 * secret-store.js — Sprint 7 T5.2: KMS / secret store SPI（可插拔密钥解析抽象）
 *
 * 设计约束（Sprint 7 关键约束 4「密钥最少接触面 INV-001」+ 0「默认关 / 可选 SPI」）：
 *   - 仅定义读取抽象，不引入任何具体 KMS/secret store 依赖 —— 默认实现读 env，
 *     「零隐式依赖」，无外部服务也能全绿。
 *   - 私钥只经 env 注入或 secret-store 解析，绝不进 MCP 参数 / 日志 / profile 明文。
 *   - 未配置 KMS → 抛带 code 的错（fail-closed，绝不静默回退到 env 而让运营者误以为
 *     在用它加密的密钥）。
 *
 * 引用格式（resolveSecretRef 统一解析）：
 *   `env:NAME`             → process.env.NAME
 *   `file:PATH`            → 读取 PATH 内容并 trim
 *   `${env:NAME}` / `${file:PATH}`（花括号包裹）也接受
 *   其它原样返回（兼容既有 env 直读密钥的引用语义）。
 *
 * createSecretResolver({ backend, provider }):
 *   backend='env'  （默认）读 env/file。
 *   backend='kms'  必须传 provider(ref) 函数；否则抛 SECRET_KMS_NOT_CONFIGURED
 *                  （接口占位，具体实现对接到真实 KMS 时注入 provider）。
 *   也可直接传 resolver 函数替代 backend。
 */
import { readFileSync } from 'node:fs';

/** 识别一个引用是否带 scheme。 */
function stripRef(ref) {
  if (ref == null) return { scheme: 'plain', value: ref };
  let s = String(ref).trim();
  const brace = /^\$\{([^}]*)\}$/.exec(s);
  if (brace) s = brace[1];
  let scheme = 'plain';
  let value = s;
  const m = /^([a-zA-Z][\w-]*):([\s\S]+)$/.exec(s);
  if (m) { scheme = m[1].toLowerCase(); value = m[2].trim(); }
  return { scheme, value };
}

/** env 后端：解析 env:/file: 两种最常用 secret ref；plain 值原样返回。 */
function envResolver() {
  return (ref) => {
    if (ref == null) return undefined;
    const { scheme, value } = stripRef(ref);
    if (scheme === 'env') return process.env[value];
    if (scheme === 'file') {
      return readFileSync(value, 'utf8').trim();
    }
    // plain / 非 env:file: → 已是密钥值，原样返回（兼容 direct 密钥 env）。
    return String(ref).trim();
  };
}

/**
 * 创建可插拔密钥解析器。
 * @param {object} [opts]
 * @param {'env'|'kms'} [opts.backend='env'] 后端类型
 * @param {(ref: string) => string|undefined} [opts.provider] 自定义解析函数（backend='kms' 必须）
 * @param {(ref: string) => string|undefined} [opts.resolve] 直接注入解析函数（等价 provider）
 * @returns {{ backend: string, resolveSecretRef: (ref: string) => string|undefined }}
 * @throws {Error} code=SECRET_KMS_NOT_CONFIGURED 当 backend='kms' 且未提供 provider
 */
export function createSecretResolver({ backend = 'env', provider, resolve } = {}) {
  const fn = resolve || provider;
  if (backend === 'kms' && typeof fn !== 'function') {
    const err = new Error(
      'createSecretResolver(backend="kms") requires a provider(ref) function. ' +
      'No concrete KMS is bundled (zero implicit dependency); wire your KMS client here.',
    );
    err.code = 'SECRET_KMS_NOT_CONFIGURED';
    throw err;
  }
  if (typeof fn === 'function') {
    return { backend, resolveSecretRef: (ref) => (ref == null ? undefined : fn(String(ref))) };
  }
  return { backend: 'env', resolveSecretRef: envResolver() };
}

/**
 * 便捷单例解析：给定 ref 与可选 resolver，返回解析后的密钥值。
 * @param {string|undefined} ref
 * @param {{ resolveSecretRef: (ref: string) => string|undefined }} [resolver]
 * @returns {string|undefined}
 */
export function resolveSecretRef(ref, resolver) {
  if (ref == null) return undefined;
  if (resolver && typeof resolver.resolveSecretRef === 'function') {
    return resolver.resolveSecretRef(String(ref));
  }
  // 默认 env resolver（与 Sprint 5/6 env 直读完全一致）。
  return envResolver()(ref);
}

/** 判断值是否为 secret ref（env:/file: 或 ${...}）。供 chain-config 决定是否走 resolver。 */
export function isSecretRef(ref) {
  if (ref == null) return false;
  return /^\$\{[^}]+\}$/.test(String(ref).trim()) || /^[a-zA-Z][\w-]*:[\s\S]+$/.test(String(ref).trim());
}