/**
 * mtls-server.js — P1.3 TLS 1.3 / mTLS 参考服务器与客户端助手（Sprint 5 T1）
 *
 * 职责：把 node:https 配置固化为「可部署的传输层安全」：
 *   - TLS 1.3 强制（minVersion: 'TLSv1.3'，禁用 TLS 1.2 及以下）
 *   - 双向认证（requestCert + ca + rejectUnauthorized：客户端必须持有本 CA 签发的证书）
 *   - 握手双方身份落审计日志
 *
 * 与 INV-009（应用层签名信封）正交：本文件只处理传输层加密与证书认证，
 * 不修改 verifyMessageEnvelope 语义；二者可组合（T5 E2E）。
 */
import https from 'node:https';

/**
 * 创建 TLS 1.3 mTLS 服务器。
 * @param {object} params
 * @param {string} params.cert 服务端证书 PEM
 * @param {string} params.key 服务端私钥 PEM
 * @param {string|string[]} params.ca 信任的客户端 CA PEM（一个或多个）
 * @param {(entry: object) => void} [params.audit] 审计回调（默认 console.error）
 * @param {(ctx: { req, res, identity, peerCert }) => void} params.onRequest 请求处理
 * @param {number} [params.port]
 * @returns {{ server: import('node:https').Server, listen: () => Promise<number>, close: () => Promise<void> }}
 */
export function createMtlsServer({ cert, key, ca, audit, onRequest, port = 0 }) {
  const auditSink = audit || ((entry) => console.error(`[audit] ${JSON.stringify(entry)}`));

  const server = https.createServer(
    {
      cert,
      key,
      ca,
      minVersion: 'TLSv1.3',                 // 强制 TLS 1.3，禁用更弱
      maxVersion: 'TLSv1.3',
      requestCert: true,                     // 请求客户端证书（mTLS）
      rejectUnauthorized: true,              // 客户端证书必须受信任，否则拒绝握手
    },
    (req, res) => {
      try {
        const peerCert = req.socket.getPeerCertificate();
        const identity = deriveIdentity(peerCert);
        auditSink({
          event: 'mtls_handshake',
          identity,
          subject: peerCert?.subject || null,
          fingerprint: peerCert?.fingerprint256 || null,
          src: req.socket.remoteAddress || null,
        });
        onRequest({ req, res, identity, peerCert });
      } catch (err) {
        recordSandboxError(err);
        res.statusCode = 500;
        res.end(JSON.stringify({ error: 'internal_error' }));
      }
    },
  );

  server.on('tlsClientError', (err, socket) => {
    // 证书拒绝/握手失败即使没到 request 也要落审计，且不因凭据错误泄露详细信息。
    auditSink({ event: 'mtls_handshake', ok: false, error: sanitizeTlsError(err), src: socket?.remoteAddress || null });
  });

  function listen() {
    return new Promise((resolveListen, rejectListen) => {
      server.once('error', rejectListen);
      server.listen(port, '127.0.0.1', () => {
        server.removeListener('error', rejectListen);
        resolveListen(server.address().port);
      });
    });
  }

  return {
    server,
    listen,
    close: () => new Promise((resolveClose) => server.close(resolveClose)),
  };
}

/** 拒绝客户端证书时的 TLS 错误，只暴露类别，不泄露内部细节。 */
function sanitizeTlsError(err) {
  const code = String(err?.code || err?.message || '');
  if (/certificate/i.test(code)) return 'tls_client_certificate_rejected';
  if (/alert/i.test(code)) return 'tls_alert';
  return 'tls_handshake_failed';
}

/** 从客户端证书提取服务身份（CN 优先）。失败 → unknown_identity（fail-closed 命名）。 */
function deriveIdentity(peerCert) {
  if (!peerCert || Object.keys(peerCert).length === 0) return 'unknown_identity';
  const subject = peerCert.subject || {};
  // Node 版本差异：detailed=false 的 subject 可能是对象 { CN }（Node>=~20）或字符串 "/CN=.."。
  const cn = typeof subject === 'string'
    ? (/CN=([^,\n]+)/.exec(subject)?.[1]?.trim())
    : (subject.CN || String(subject.OU ?? '') || '');
  return cn || (typeof subject === 'string' ? subject : '') || 'unknown_identity';
}

function recordSandboxError(err) {
  console.error(`[mtls-server] request error: ${err?.message}`);
}

/**
 * 创建 mTLS 客户端（node:https，无外部依赖）。用于测试/示例向 mTLS 服务端发请求。
 * @param {object} params
 * @param {string} params.ca 信任的服务端 CA PEM
 * @param {string} params.cert 客户端证书 PEM
 * @param {string} params.key 客户端私钥 PEM
 * @param {{ maxVersion, minVersion }} [params.tls] TLS 版本上限（默认强制 1.3）
 * @returns {(path: string, body?: object) => Promise<{ status: number, data: any }>}
 */
export function createMtlsClient({ ca, cert, key, tls = {} }) {
  return function mtlsRequest(path, body) {
    return new Promise((resolveRequest, rejectRequest) => {
      const target = new URL(path);
      const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
      const options = {
        hostname: target.hostname,
        port: target.port || 443,
        path: `${target.pathname}${target.search}`,
        method: body === undefined ? 'GET' : 'POST',
        headers: payload ? { 'content-type': 'application/json', 'content-length': payload.length } : undefined,
        ca,
        cert,
        key,
        minVersion: tls.minVersion || 'TLSv1.3',
        maxVersion: tls.maxVersion || 'TLSv1.3',
        rejectUnauthorized: true,
      };
      const req = https.request(options, (res) => {
        let raw = '';
        res.on('data', (c) => { raw += c; });
        res.on('end', () => {
          let data;
          try { data = raw ? JSON.parse(raw) : null; } catch { data = raw; }
          resolveRequest({ status: res.statusCode, data });
        });
      });
      req.on('error', rejectRequest);
      if (payload) req.write(payload);
      req.end();
    });
  };
}