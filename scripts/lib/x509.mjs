/**
 * x509.mjs — 最小自含 X.509 v3 证书构造器（纯 node:crypto，无外部依赖）
 *
 * 用途：Sprint 5 P1.3 开发用 mTLS 自签 CA（不依赖系统 openssl，Windows 可跑）。
 * 支持：Ed25519 密钥对、自签 CA、为 server/client 签发叶子证书，
 *       含 basicConstraints / keyUsage / subjectKeyIdentifier /
 *       authorityKeyIdentifier / subjectAltName / extendedKeyUsage 扩展。
 *
 * 仅供开发/测试。生产 mTLS 证书签发须对接 service identity / KMS（Sprint 7）。
 */
import { generateKeyPairSync, sign, createHash, createPrivateKey, X509Certificate } from 'node:crypto';
import net from 'node:net';

/* ------------------------------ ASN.1 DER ------------------------------ */

function encodeLength(len) {
  if (len < 0x80) return Buffer.from([len]);
  const bytes = [];
  let n = len;
  while (n > 0) { bytes.unshift(n & 0xff); n = Math.floor(n / 256); }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, content) {
  const c = Buffer.isBuffer(content) ? content : Buffer.from(content);
  return Buffer.concat([Buffer.from([tag]), encodeLength(c.length), c]);
}

function seq(...items) { return tlv(0x30, Buffer.concat(items)); }
function setItems(...items) { return tlv(0x31, Buffer.concat(items)); }

/** BER/DER OID base-128 编码。 */
function oidBytes(parts) {
  const out = [];
  out.push(parts[0] * 40 + parts[1]);
  for (let i = 2; i < parts.length; i++) {
    const group = [];
    group.unshift(parts[i] & 0x7f);
    let v = Math.floor(parts[i] / 128);
    while (v > 0) { group.unshift((v & 0x7f) | 0x80); v = Math.floor(v / 128); }
    out.push(...group);
  }
  return out;
}
const oid = (parts) => tlv(0x06, oidBytes(parts));

function integer(n) {
  const bytes = [];
  let v = n;
  do { bytes.unshift(v & 0xff); v = Math.floor(v / 256); } while (v > 0);
  if (bytes[0] & 0x80) bytes.unshift(0x00); // 保持正数
  return tlv(0x02, Buffer.from(bytes));
}

/** BIT STRING：首个字节为 unused-bits 计数。 */
function bitString(contentBytes, unusedBits = 0) {
  return tlv(0x03, Buffer.concat([Buffer.from([unusedBits]), contentBytes]));
}
const octetString = (c) => tlv(0x04, Buffer.isBuffer(c) ? c : Buffer.from(c));
const booleanTrue = tlv(0x01, Buffer.from([0xff]));
function utcTimeString(ms) {
  const d = new Date(ms);
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
}
const genTime = (ms) => tlv(0x18, Buffer.from(utcTimeString(ms), 'ascii'));
const utf8 = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));

/** X.500 Name = RDNSequence（SEQUENCE OF SET OF AttributeTypeAndValue）。 */
function Name(attrs) {
  const rdns = attrs.map(({ t, v }) => setItems(seq(oid(t), utf8(v))));
  return seq(...rdns);
}

/* ------------------------- 预定义常量/构造 ------------------------- */

const OID = {
  ed25519: [1, 3, 101, 112],
  commonName: [2, 5, 4, 3],
  basicConstraints: [2, 5, 29, 19],
  keyUsage: [2, 5, 29, 15],
  subjectKeyIdentifier: [2, 5, 29, 14],
  authorityKeyIdentifier: [2, 5, 29, 35],
  subjectAltName: [2, 5, 29, 17],
  extendedKeyUsage: [2, 5, 29, 37],
  serverAuth: [1, 3, 6, 1, 5, 5, 7, 3, 1],
  clientAuth: [1, 3, 6, 1, 5, 5, 7, 3, 2],
};

const ed25519Alg = seq(oid(OID.ed25519));

/** keyUsage 位掩码（RFC 3280 位索引）。返回 BIT STRING DER（作为扩展值）。 */
function keyUsageBitString(usages) {
  const INDEX = {
    digitalSignature: 0, contentCommitment: 1, keyEncipherment: 2,
    dataEncipherment: 3, keyAgreement: 4, keyCertSign: 5, cRLSign: 6,
    encipherOnly: 7, decipherOnly: 8,
  };
  let maxBit = 0;
  const bytes = [];
  for (const u of usages) {
    const bit = INDEX[u];
    if (bit === undefined) continue;
    maxBit = Math.max(maxBit, bit);
    const octet = Math.floor(bit / 8);
    bytes[octet] = (bytes[octet] || 0) | (1 << (7 - (bit % 8)));
  }
  const unused = (8 - ((maxBit + 1) % 8)) % 8;
  return bitString(Buffer.from(bytes), unused);
}

/** 通用 Extension：value 为 OCTET STRING 内的 DER。 */
function extension(oidParts, critical, valueDer) {
  const parts = [oid(oidParts)];
  if (critical) parts.push(booleanTrue);
  parts.push(octetString(valueDer));
  return seq(...parts);
}

function spkiEd25519(pubBytes) {
  return seq(ed25519Alg, bitString(pubBytes, 0));
}

/* ----------------------------- 证书构造 ----------------------------- */

/** 生成 Ed25519 密钥对，返回 { privateKeyObject, publicKeyObject, publicPem, privatePem }。 */
export function generateEd25519Keypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    privateKey,
    publicKey,
    publicKeyBytes: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32),
    publicPem: publicKey.export({ format: 'pem', type: 'spki' }),
    privatePem: privateKey.export({ format: 'pem', type: 'pkcs8' }),
  };
}

/**
 * 构造并签名一张 X.509 v3 证书。
 * SPKI 使用（subject 的）keypair 公钥；签名使用 signingKey（issuer 私钥）。
 * @param {object} params
 * @param {{publicKeyBytes}} params.keypair subject 持有者密钥对（决定 SPKI）
 * @param {object} params.signingKey 签发者私钥（KeyObject）——叶子证书必须传 CA 私钥
 * @param {Array<{t:number[], v:string}>} params.subject subject 属性
 * @param {Array<{t:number[], v:string}>} params.issuer issuer 属性
 * @param {Buffer} params.issuerKeyId 签发者 subjectKeyIdentifier（叶子证书 aki 用）
 * @param {number} params.notBefore 毫秒
 * @param {number} params.notAfter 毫秒
 * @param {Array} params.extensions 已编码的 Extension DER 数组
 * @param {number} [params.serial]
 * @returns {string} PEM
 */
export function buildCertificate({ keypair, signingKey, subject, issuer, issuerKeyId = null, notBefore, notAfter, extensions = [], serial }) {
  const pubBytes = keypair.publicKeyBytes;
  const serialNum = serial !== undefined
    ? serial
    : Number((BigInt(`0x${createHash('sha256').update(pubBytes).digest('hex').slice(0, 14)}`) ) % 0x7fffffffffn);

  const body = seq(
    tlv(0xa0, integer(2)),            // v3, EXPLICIT
    integer(serialNum),
    ed25519Alg,
    Name(issuer),
    seq(genTime(notBefore), genTime(notAfter)),
    Name(subject),
    spkiEd25519(pubBytes),
    tlv(0xa3, seq(...extensions)),    // [3] EXPLICIT Extensions
  );

  const signer = signingKey ?? keypair.privateKey;
  const sig = sign(null, body, signer);
  return certPem(seq(body, ed25519Alg, bitString(sig, 0)));
}

function certPem(der) {
  const b64 = der.toString('base64');
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

/* --------------------------- 便捷构造器 --------------------------- */

const DAY = 86400 * 1000;

/**
 * 创建一张自签 CA 证书。
 * @param {object} [opts] { cn, days }
 * @returns {{ cert: string, keypair }} keypair 含 privateKeyObject（可再签）。
 */
export function createCa({ cn = 'Aegis Vault Dev Root CA', days = 3650 } = {}) {
  const keypair = generateEd25519Keypair();
  const now = Date.now();
  const keyId = sha1(keypair.publicKeyBytes);
  const extensions = [
    extension(OID.basicConstraints, true, seq(booleanTrue)),
    extension(OID.keyUsage, true, keyUsageBitString(['keyCertSign', 'cRLSign', 'digitalSignature'])),
    extension(OID.subjectKeyIdentifier, false, octetString(keyId)),
  ];
  const cert = buildCertificate({
    keypair,
    signingKey: keypair.privateKey,
    subject: caSubject(cn),
    issuer: caSubject(cn),
    notBefore: now - DAY,
    notAfter: now + days * DAY,
    extensions,
  });
  return { cert, keypair, keyId, subject: caSubject(cn) };
}

/**
 * 从「受控 CA」签发的既有 CA（cert + 私钥 PEM）装载为可继续签发叶子的 ca 对象
 * （生产 mTLS 证书签发对接 service identity / secret-store SPI，见 Sprint 7 T5）。
 * keyId 由 CA 公钥 SPKI 派生（与叶子证书 AKI 对齐）；subject 从 CA cert CN 重建。
 * @param {object} params
 * @param {string} params.cert CA 证书 PEM
 * @param {string} params.key CA 私钥 PEM（pkcs8）
 * @returns {{ cert: string, keypair: { privateKey: KeyObject }, keyId: Buffer, subject: Array<{t, v}> }}
 */
export function loadCa({ cert, key }) {
  const x = new X509Certificate(cert);
  const spki = x.publicKey.export({ type: 'spki', format: 'der' });
  const pubBytes = spki.subarray(-32); // Ed25519 公钥恒为末 32 字节
  const privateKey = createPrivateKey(key);
  const cn = /CN=([^,\n]+)/.exec(x.subject)?.[1]?.trim() || 'NexusGenesis CA';
  return { cert, keypair: { privateKey }, publicKey: x.publicKey, keyId: sha1(pubBytes), subject: caSubject(cn) };
}

/**
 * 签发一张叶子证书（server/client）。
 * @param {object} opts
 * @param {{cert:string, keypair:object, keyId:Buffer}} opts.ca CA 材料
 * @param {object} opts.keypair 叶子证书的持有者密钥对
 * @param {string} opts.cn commonName
 * @param {string[]} opts.eku serverAuth | clientAuth
 * @param {string[]} [opts.dns] SAN DNS 条目
 * @param {string[]} [opts.ip] SAN IP 条目（点分/冒号字符串）
 * @param {number} [opts.days]
 * @param {number} [opts.notBefore] 覆盖 notBefore（毫秒，默认 now-1d）
 * @param {number} [opts.notAfter] 覆盖 notAfter（毫秒，默认 now+days）
 * @returns {{ cert: string, keypair }}
 */
export function issueLeaf({ ca, keypair, cn, eku, dns = [], ip = [], days = 825, notBefore, notAfter }) {
  const now = Date.now();
  const keyId = sha1(keypair.publicKeyBytes);
  const sanEntries = [];
  for (const h of dns) sanEntries.push(tlv(0x82, Buffer.from(h, 'ascii'))); // [2] DNS (IA5String)
  for (const a of ip) sanEntries.push(tlv(0x87, ipBytes(a)));               // [7] IP (OCTET STRING)
  const extensions = [
    extension(OID.basicConstraints, true, seq()), // cA = false
    extension(OID.keyUsage, true, keyUsageBitString(['digitalSignature', 'keyEncipherment'])),
    extension(OID.subjectKeyIdentifier, false, octetString(keyId)),
    extension(OID.authorityKeyIdentifier, false, seq(tlv(0x80, ca.keyId))), // [0] keyIdentifier
    extension(OID.subjectAltName, false, seq(...sanEntries)),
    extension(OID.extendedKeyUsage, false, seq(...eku.map((e) => oid(e === 'serverAuth' ? OID.serverAuth : OID.clientAuth)))),
  ];
  const cert = buildCertificate({
    keypair,
    signingKey: ca.keypair.privateKey,
    subject: [{ t: OID.commonName, v: cn }],
    issuer: ca.subject,
    issuerKeyId: ca.keyId,
    notBefore: notBefore ?? (now - DAY),
    notAfter: notAfter ?? (now + days * DAY),
    extensions,
  });
  return { cert, keypair };
}

/** 从 CA 构造收集其 subject DN，以便叶子证书 issuer 引用。 */
export function caSubject(cn = 'Aegis Vault Dev Root CA') {
  return [{ t: OID.commonName, v: cn }];
}

/* --------------------------- 小工具 --------------------------- */
function sha1(bytes) { return createHash('sha1').update(bytes).digest(); }
function ipBytes(addr) {
  if (addr.includes(':')) {
    if (!net.isIPv6(addr)) throw new Error(`invalid IPv6 addr: ${addr}`);
    return ipv6ToBytes(addr);
  }
  if (!net.isIPv4(addr)) throw new Error(`invalid IPv4 addr: ${addr}`);
  return Buffer.from(addr.split('.').map(Number));
}
/** IPv6 字符串 → 16 字节（支持 IPv4-mapped 与 :: 压缩）。 */
function ipv6ToBytes(addr) {
  const bridge = addr.indexOf('::') >= 0;
  let head = bridge ? addr.split('::')[0] : addr;
  let tail = bridge ? addr.split('::')[1] : '';
  const parts = [];
  let v4 = null;
  if (head.includes('.') || tail.includes('.')) {
    const v4part = (head.includes('.')) ? head : tail;
    const hex = (head.includes('.')) ? head : tail;
    if (hex === v4part) {
      // 纯 IPv4-mapped：两段压缩，v4 占最后两个 group
      v4 = v4part.split('.').map(Number);
      head = head === v4part ? '' : head;
      tail = ''; // v4 已消费
    }
  }
  const headGroups = head ? head.split(':').map((g) => g || '0') : [];
  const tailGroups = bridge ? (tail ? tail.split(':').map((g) => g || '0') : []) : [];
  const totalHexGroups = 8 - (v4 ? 2 : 0);
  const gap = totalHexGroups - headGroups.length - tailGroups.length;
  const all = [
    ...headGroups.map(Number),
    ...(bridge && gap > 0 ? Array(gap).fill(0) : []),
    ...tailGroups.map(Number),
  ];
  if (v4) all.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
  const out = Buffer.alloc(16);
  all.forEach((group, i) => { if (group !== undefined) out.writeUInt16BE(group & 0xffff, i * 2); });
  return out;
}

export { OID };