/**
 * aegis-vault — Signer subprocess (process-isolated key holder)
 *
 * DESIGN
 * ──────
 * The Signer runs as a separate child process (signer-worker.js) that holds
 * the private key as ShardedSecret and exposes only a signing RPC interface
 * over stdio. The parent process can only request signatures, never access
 * the key material.
 *
 * THREAT MODEL
 * ────────────
 *   Addressed:  Parent process fully compromised (prompt injection, supply
 *               chain attack, memory dump). Attacker can only request
 *               signatures, subject to spend policy. Maximum loss bounded.
 *   Not addressed: Physical attacks (DMA, cold boot) — requires TEE.
 *   Not addressed: Worker process itself compromised (requires seccomp /
 *               AppArmor / SELinux profile — see deploy docs).
 *
 * IPC PROTOCOL (stdio, JSON-line, LF-terminated)
 * ───────────────────────────────────────────────
 *   Parent → Child:
 *     {"type":"init","envelope":{...},"password":"...","policy":{...}}
 *     {"type":"sign","requestId":1,"hash":"0xabcdef...","amount":"50"}   // legacy
 *     {"type":"sign_intent","requestId":1,"payload":{...}}               // P0-4
 *     {"type":"ping","requestId":0}
 *     {"type":"exit"}
 *
 *   The `amount` field on legacy sign requests carries the transaction's real
 *   value. It is MANDATORY when a spend policy is configured (the worker
 *   fails closed without it) and ignored otherwise. P0-4 replaces this for
 *   asset signing: sign_intent embeds the amount inside the signed payload,
 *   so the worker's policy check and the signed content are the same object.
 *
 *   Child → Parent:
 *     {"type":"init_ok","address":"ng1..."}
 *     {"type":"init_fail","error":"..."}
 *     {"type":"signature","requestId":1,"sig":"0x..."}
 *     {"type":"sign_fail","requestId":1,"error":"..."}
 *     {"type":"sign_timelock","requestId":1,"timelockMs":86400000,"scheduledAt":...}
 *     {"type":"pong","requestId":0}
 *     {"type":"exiting","reason":"..."}
 *
 * KNOWN ARCHITECTURAL LIMITATION (legacy 'sign' channel) — amount-hash
 * unlinkability
 * ──────────────────────────────────────────────────────────
 * The legacy 'sign' channel applies spend-policy checks to the `amount` field
 * it receives via IPC, but it has NO way to verify that the `amount` matches
 * the `hash` being signed. A compromised parent process can always send
 * `amount: "1"` alongside a hash of a million-token transfer — the worker
 * will approve the sign because the policy check uses the (fake) amount,
 * while the signature is applied to the (real, high-value) hash.
 *
 * P0-4 FIX: asset signing MUST use the 'sign_intent' channel instead. There,
 * the signed content IS the payload and the amount is read from inside it,
 * so the policy check and the signed amount are structurally the same value —
 * a compromised parent cannot lie about the amount. The legacy 'sign' channel
 * remains for hash-signing callers that bind the amount elsewhere (e.g. an
 * on-chain Smart Account that independently validates the transaction amount).
 * The session-key layer (verifier) MUST still independently validate the
 * transaction's real amount against maxPerTx/maxDaily before acceptance.
 *
 * USAGE
 * ─────
 *   import { spawnSigner } from 'aegis-vault';
 *   const signer = await spawnSigner({ envelope, password, policy });
 *   const sig = await signer.sign('0xabcdef...');            // legacy hash sign
 *   const sig2 = await signer.signIntent({ type:'agent_asset_intent', amount:'50', ... });
 *   await signer.close();
 *
 * BREAKING CHANGE (v2.0): sign()'s second argument changed from a bare
 *   timeoutMs (number) to an options object {amount, timeoutMs}. The
 *   common case sign(hash) is unaffected. sign(hash, 5000) will throw.
 *
 * SECURITY NOTES
 * ──────────────
 *   1. Password sent once via IPC (Unix domain socket / named pipe, not
 *      network stack). Not visible in /proc/.../environ or /proc/.../cmdline.
 *   2. After init, the worker enters a strict read loop: only stdin
 *      (JSON-line), no file system, no network, no module loading.
 *      Seccomp hardening is deploy-time, not baked in.
 *   3. Worker exits after configurable idle timeout (default 5 min).
 *   4. Private key held as ShardedSecret — never contiguous plaintext in
 *      either the parent or worker process memory.
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { isValidEnvelope } from './encryption.js';

// ─── Constants ───────────────────────────────────────────────────────────
const SIGNER_INIT_TIMEOUT_MS = 15000;
const SIGNER_PER_REQUEST_TIMEOUT_MS = 30000;
const SIGNER_PING_TIMEOUT_MS = 5000;
const SIGNER_GRACEFUL_SHUTDOWN_MS = 2000;
/** Max bytes for a signMessage payload (metadata envelopes are small). */
export const SIGN_MESSAGE_MAX_BYTES = 64 * 1024;

/**
 * A bare or 0x-prefixed 64-char hex string — the exact shape of a
 * sha256-sized transaction/intent hash (e.g. hashAssetIntent() output).
 * Refused on the policy-less signMessage channel (see SignerHandle.signMessage).
 */
const HASH_SHAPED_RE = /^(?:0x)?[0-9a-fA-F]{64}$/;

// ─── Parent-side SignerHandle ────────────────────────────────────────────

/**
 * Handle to a spawned Signer child process.
 * Call `sign()` to request signatures, `close()` to terminate.
 * Never has access to the private key material.
 */
export class SignerHandle {
  constructor(child) {
    this._child = child;
    this._pending = new Map();
    this._requestId = 0;
    this._closed = false;

    let buffer = '';
    this._child.stdout.on('data', (chunk) => {
      buffer += chunk.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          this._handleResponse(JSON.parse(line));
        } catch { /* malformed — ignore */ }
      }
    });

    this._child.stderr.on('data', (chunk) => {
      console.error(`[signer:${this._child.pid}] ${chunk.toString().trim()}`);
    });

    this._child.on('exit', (code, signal) => {
      this._closed = true;
      const reason = signal ? `signal ${signal}` : `exit ${code}`;
      for (const [, pending] of this._pending) {
        clearTimeout(pending.timer);
        pending.reject(new Error(`Signer process terminated (${reason})`));
      }
      this._pending.clear();
    });
  }

  _handleResponse(msg) {
    // Ping uses a special string key 'ping' (not a number).
    if (msg.type === 'pong') {
      const pending = this._pending.get('ping');
      if (pending) {
        clearTimeout(pending.timer);
        this._pending.delete('ping');
        pending.resolve();
      }
      return;
    }
    const pending = this._pending.get(msg.requestId);
    if (!pending) return;
    clearTimeout(pending.timer);
    this._pending.delete(msg.requestId);
    if (msg.type === 'signature') {
      pending.resolve(msg.sig);
    } else if (msg.type === 'sign_fail') {
      pending.reject(new Error(msg.error || 'sign failed'));
    } else if (msg.type === 'sign_timelock') {
      // Medium-tier timelock: resolve with timelock info instead of rejecting.
      pending.resolve({
        timelocked: true,
        timelockMs: msg.timelockMs,
        scheduledAt: msg.scheduledAt
      });
    }
  }

  /**
   * Request a signature from the isolated Signer process.
   *
   * @param {string} hash - Transaction hash (hex, 0x-prefixed) to sign
   * @param {object} [opts]
   * @param {string} [opts.amount] - Transaction amount (decimal string).
   *   REQUIRED when a spend policy is configured on the signer — the worker
   *   fails closed on policy checks without a real amount. Omit for pure
   *   message signing on policy-less signers.
   * @param {number} [opts.timeoutMs=30000] - Per-request timeout
   * @returns {Promise<string|{timelocked:true, timelockMs:number, scheduledAt:number}>}
   *   Resolves with a 0x-prefixed hex signature, OR — when the request
   *   lands in the medium tier under three-tier authorization — an object
   *   describing the 24h time-lock. Check `typeof result === 'string'`
   *   (or `result.timelocked`) before treating the value as a signature.
   */
  async sign(hash, { amount, timeoutMs = SIGNER_PER_REQUEST_TIMEOUT_MS } = {}) {
    if (this._closed) throw new Error('Signer is closed');
    if (!hash || typeof hash !== 'string' || !/^0x[0-9a-fA-F]+$/.test(hash)) {
      throw new Error('Invalid hash — must be 0x-prefixed hex string');
    }
    const id = ++this._requestId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pending.delete(id);
        reject(new Error(`Signer timeout (${timeoutMs}ms) for request ${id}`));
      }, timeoutMs);
      this._pending.set(id, { resolve, reject, timer });
      this._send({ type: 'sign', requestId: id, hash, amount });
    });
  }

  /**
   * Request a policy-less signature over an arbitrary message string.
   *
   * This channel is for NON-VALUE-BEARING metadata (task claim/submit/verify/
   * publish, forum actions, protocol bookkeeping). No spend policy is applied
   * and no amount is required — the signed string is the message itself, so a
   * verifier checks `verify(message, sig, publicKey)` exactly as it would for
   * `wallet.sign(message)`. Value-bearing (asset/transaction) signing MUST go
   * through `sign()` so the worker-side spend policy and amount binding apply.
   *
   * Hash-shaped messages (a bare or 0x-prefixed 64-char hex string — the exact
   * shape of a transaction/intent hash such as hashAssetIntent() output) are
   * REFUSED on both this side (fail fast) and, authoritatively, inside the
   * worker. Without that guard a compromised parent could route a
   * value-bearing hash through the policy-less channel and bypass the
   * worker-side spend policy (INV-002).
   *
   * @param {string} message - The exact message string to sign.
   * @param {object} [opts]
   * @param {number} [opts.timeoutMs=30000] - Per-request timeout
   * @returns {Promise<string>} 0x-prefixed hex signature
   */
  async signMessage(message, { timeoutMs = SIGNER_PER_REQUEST_TIMEOUT_MS } = {}) {
    if (this._closed) throw new Error('Signer is closed');
    if (!message || typeof message !== 'string' || message.length === 0) {
      throw new Error('Invalid message — must be a non-empty string');
    }
    if (HASH_SHAPED_RE.test(message)) {
      throw new Error('signMessage refuses hash-shaped messages — value-bearing hashes must go through sign() with policy (INV-002)');
    }
    // P0-4 cross-validation: fail fast on the parent side for JSON-serialized
    // asset-intent payloads (the exact shape the on-chain verifier
    // verifyAgentAssetSignature trusts). The worker refuses these
    // authoritatively; this guard just gives callers an immediate, local error.
    let parsed;
    try { parsed = JSON.parse(message); } catch { parsed = null; }
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        && parsed.type === 'agent_asset_intent') {
      throw new Error('signMessage refuses asset-intent payloads — value-bearing intents must go through signIntent() with policy (INV-002/P0-4)');
    }
    if (Buffer.byteLength(message, 'utf8') > SIGN_MESSAGE_MAX_BYTES) {
      throw new Error(`Message exceeds ${SIGN_MESSAGE_MAX_BYTES} bytes`);
    }
    const id = ++this._requestId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pending.delete(id);
        reject(new Error(`Signer timeout (${timeoutMs}ms) for request ${id}`));
      }, timeoutMs);
      this._pending.set(id, { resolve, reject, timer });
      this._send({ type: 'sign_message', requestId: id, message });
    });
  }

  /**
   * Request a signature over a structured asset-intent payload (P0-4).
   *
   * The payload IS the signed content and its `amount` is embedded inside it,
   * so the worker derives the amount for its spend-policy check from the very
   * bytes it signs — not from a separate parent-supplied field. This closes
   * the amount-hash unlinkability limitation of the legacy `sign()` channel:
   * a compromised parent cannot request a "small" policy check over a "large"
   * signed amount, because the checked amount and the signed amount are the
   * same object.
   *
   * The signature verifies over `JSON.stringify(payload)` — the same string
   * an on-chain verifier recomputes when it decodes the amount from the
   * payload (see aegis-agent-sdk verifyAgentAssetSignature).
   *
   * @param {object} payload - canonical agent asset intent (must carry
   *   type='agent_asset_intent' and a non-negative numeric `amount`)
   * @param {object} [opts]
   * @param {number} [opts.timeoutMs=30000] - Per-request timeout
   * @returns {Promise<string|{timelocked:true, timelockMs:number, scheduledAt:number}>}
   *   Resolves with a 0x-prefixed hex signature, or a timelock object when the
   *   amount lands in the medium tier under three-tier authorization.
   */
  async signIntent(payload, { timeoutMs = SIGNER_PER_REQUEST_TIMEOUT_MS } = {}) {
    if (this._closed) throw new Error('Signer is closed');
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw new Error('Invalid intent payload — must be an object');
    }
    const id = ++this._requestId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pending.delete(id);
        reject(new Error(`Signer timeout (${timeoutMs}ms) for request ${id}`));
      }, timeoutMs);
      this._pending.set(id, { resolve, reject, timer });
      this._send({ type: 'sign_intent', requestId: id, payload });
    });
  }

  /**
   * Ping the signer process (health check).
   * @param {number} [timeoutMs=5000]
   */
  async ping(timeoutMs = SIGNER_PING_TIMEOUT_MS) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pending.delete('ping');
        reject(new Error('Signer ping timeout'));
      }, timeoutMs);
      this._pending.set('ping', { resolve, reject, timer });
      this._send({ type: 'ping', requestId: 0 });
    });
  }

  /**
   * Gracefully terminate the Signer process.
   */
  async close() {
    if (this._closed) return;
    this._closed = true;
    this._send({ type: 'exit' });
    // Give it 2s to exit gracefully, then SIGKILL.
    setTimeout(() => {
      try { this._child.kill('SIGKILL'); } catch {}
    }, SIGNER_GRACEFUL_SHUTDOWN_MS);
    return new Promise((resolve) => {
      this._child.on('exit', () => resolve());
      this._child.on('error', () => resolve());
    });
  }

  _send(msg) {
    try {
      this._child.stdin.write(JSON.stringify(msg) + '\n');
    } catch {
      if (!this._closed) {
        console.error('[signer] write error');
      }
    }
  }
}

// ─── spawnSigner ─────────────────────────────────────────────────────────

/**
 * Spawn an isolated signer child process.
 *
 * The child process:
 *   - Decrypts the private key from the envelope
 *   - Holds it as ShardedSecret (never contiguous plaintext)
 *   - Accepts only sign requests via stdio JSON-line protocol
 *   - Enforces spend policy before signing
 *   - Exits after idle timeout
 *
 * @param {object} opts
 * @param {object} opts.envelope - Encrypted key envelope (from encryptPrivateKey)
 * @param {string} opts.password - Decryption password (sent once via IPC)
 * @param {object} [opts.policy] - Spend policy (see takeover.js)
 * @param {number} [opts.idleTimeoutMs=300000] - Idle timeout before auto-exit
 * @returns {Promise<SignerHandle>}
 */
export async function spawnSigner({
  envelope,
  password,
  policy,
  idleTimeoutMs = 5 * 60 * 1000
} = {}) {
  if (!envelope || !isValidEnvelope(envelope)) {
    throw new Error('Invalid or missing envelope');
  }
  if (!password || typeof password !== 'string' || password.length < 8) {
    throw new Error('Password must be at least 8 characters');
  }

  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const workerPath = path.join(__dirname, 'signer-worker.js');

  const child = spawn(process.execPath, [workerPath], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, NODE_ENV: process.env.NODE_ENV || 'production' },
    execArgv: ['--no-deprecation']
  });

  const handle = new SignerHandle(child);

  // Wait for init_ok / init_fail.
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error('Signer init timeout'));
    }, SIGNER_INIT_TIMEOUT_MS);

    const onData = (chunk) => {
      const lines = chunk.toString().split('\n');
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const msg = JSON.parse(line);
          if (msg.type === 'init_ok') {
            clearTimeout(timer);
            child.stdout.removeListener('data', onData);
            resolve(msg);
          } else if (msg.type === 'init_fail') {
            clearTimeout(timer);
            child.stdout.removeListener('data', onData);
            reject(new Error(msg.error || 'Signer init failed'));
          }
        } catch {}
      }
    };
    child.stdout.on('data', onData);

    handle._send({
      type: 'init',
      envelope,
      password,
      policy,
      idleTimeoutMs
    });
  });

  return handle;
}