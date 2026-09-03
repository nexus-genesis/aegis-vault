#!/usr/bin/env node
/**
 * aegis-vault — Signer worker entry point
 *
 * This file is the child process entry point for the Signer subprocess.
 * It is spawned by signer.js (spawnSigner) and communicates via stdin/stdout
 * using a JSON-line protocol. It is NOT meant to be imported — only executed.
 *
 * SECURITY MODEL
 * ──────────────
 * - Key material is held as ShardedSecret (XOR 2-of-2 shards, never contiguous
 *   plaintext in memory). See secure.js for the boundary statement.
 * - After init, the worker enters a strict read loop: only stdin (JSON-line).
 * - No file system access after init (the imported modules are loaded at
 *   startup before the first message is processed).
 * - No network access (the process has no listening sockets or outgoing
 *   connections; seccomp at deploy time can enforce this).
 * - Password is received once via stdin (Node.js IPC = Unix domain socket /
 *   named pipe, not the network stack). Not visible in /proc/.../environ
 *   or /proc/.../cmdline.
 * - Idle timeout (default 5 min) ensures the process does not persist
 *   indefinitely.
 * - Input cap (1 MiB per message) prevents OOM-then-swap attacks.
 *
 * KNOWN LIMITATION — amount-hash unlinkability:
 *   The worker trusts the `amount` field from the parent process. It cannot
 *   verify that the amount matches the `hash` being signed. A compromised
 *   parent can lie about the amount. See signer.js for mitigation strategy.
 */

import { ShardedSecret, disableCoreDumps } from './secure.js';
import { decryptPrivateKey, isValidEnvelope } from './encryption.js';
import { generateAddress } from './address.js';
import { signSync } from './pqc.js';
import { checkSpendAllowedTiered } from './takeover.js';

// ─── Bootstrap ───────────────────────────────────────────────────────────
// Immediately disable core dumps in the child process.
disableCoreDumps();

// Least privilege: drop to an unprivileged account before handling any key
// material. Enabled with NGX_SIGNER_DOWNGRADE=1 when started as root
// (containers / system daemons). POSIX only — on Windows this is a no-op.
//
// Pair with the reference seccomp profile at deploy/seccomp/signer-seccomp.json
// (Docker `--security-opt seccomp=...`) to also constrain the syscall surface.
try {
  if (
    process.env.NGX_SIGNER_DOWNGRADE === '1' &&
    typeof process.getuid === 'function' &&
    process.getuid() === 0
  ) {
    process.setgid('nobody');
    process.setuid('nobody');
    console.error('[signer-worker] privileges dropped to nobody');
  }
} catch (err) {
  console.error(`[signer-worker] privilege downgrade FAILED, refusing to continue: ${err.message}`);
  process.exit(1);
}

// ─── State ───────────────────────────────────────────────────────────────
let sharded = null;     // ShardedSecret holding the private key
let publicKey = null;   // Public key (Buffer)
let address = null;     // Wallet address (string)
let policy = null;      // Spend policy (object)
let idleTimer = null;   // Idle timeout timer
let currentIdleTimeout = 5 * 60 * 1000; // Idle timeout in ms

// ─── Helpers ─────────────────────────────────────────────────────────────

/** Write a JSON-line response to stdout. */
function respond(msg) {
  try {
    process.stdout.write(JSON.stringify(msg) + '\n');
  } catch {
    // stdout closed — exit.
    process.exit(1);
  }
}

/** Reset the idle timeout (called after each successful request). */
function resetIdleTimer() {
  if (idleTimer) clearTimeout(idleTimer);
  if (currentIdleTimeout > 0) {
    idleTimer = setTimeout(() => {
      respond({ type: 'exiting', reason: 'idle_timeout' });
      process.exit(0);
    }, currentIdleTimeout);
    idleTimer.unref();
  }
}

// ─── Message handler ─────────────────────────────────────────────────────

function handleMessage(msg) {
  try {
    switch (msg.type) {
      case 'init': {
        if (!isValidEnvelope(msg.envelope)) {
          respond({ type: 'init_fail', error: 'Invalid envelope' });
          return;
        }
        if (!msg.password || msg.password.length < 8) {
          respond({ type: 'init_fail', error: 'Invalid password' });
          return;
        }

        try {
          // Decrypt private key from envelope.
          const privateKey = decryptPrivateKey(msg.envelope, msg.password);
          // Immediately shard it; ShardedSecret constructor zeroes the caller's copy.
          sharded = new ShardedSecret(privateKey);
          publicKey = Buffer.from(msg.envelope.metadata.publicKey, 'hex');
          address = msg.envelope.metadata.address || generateAddress(publicKey);
          policy = msg.policy || {};
          currentIdleTimeout = msg.idleTimeoutMs || (5 * 60 * 1000);

          respond({ type: 'init_ok', address });
          resetIdleTimer();
        } catch (e) {
          respond({ type: 'init_fail', error: e.message });
        }
        break;
      }

      case 'sign': {
        if (!sharded) {
          respond({ type: 'sign_fail', requestId: msg.requestId, error: 'Not initialized' });
          return;
        }
        resetIdleTimer();

        const hash = msg.hash;
        if (!hash || typeof hash !== 'string' || !/^0x[0-9a-fA-F]+$/.test(hash)) {
          respond({ type: 'sign_fail', requestId: msg.requestId, error: 'Invalid hash (must be 0x-hex)' });
          return;
        }

        // Enforce spend policy (if configured) with three-tier authorization.
        // SECURITY FIX: the check MUST use the transaction's real amount
        // (msg.amount), never a policy field. An earlier revision passed
        // `policy.maxPerTx` here, which (a) never reflected the actual
        // transaction value and (b) could push every request into the
        // medium-timelock branch. When a policy is configured but the
        // caller did not supply an amount, fail CLOSED.
        if (policy.type) {
          if (msg.amount === undefined || msg.amount === null) {
            respond({
              type: 'sign_fail',
              requestId: msg.requestId,
              error: 'Policy is configured but the sign request carries no amount (fail-closed)'
            });
            return;
          }
          const result = checkSpendAllowedTiered(policy, { amount: msg.amount });
          if (!result.allowed) {
            respond({ type: 'sign_fail', requestId: msg.requestId, error: result.reason || 'Policy denied' });
            return;
          }
          // If the result includes a timelock, communicate it back.
          if (result.tier === 'medium-timelock') {
            respond({ type: 'sign_timelock', requestId: msg.requestId, timelockMs: result.timelockMs, scheduledAt: result.scheduledAt });
            return;
          }
        }

        // Sign with transient use: plaintext key exists only inside the callback.
        try {
          const sigHex = sharded.use(pk => {
            const sig = signSync(hash, pk);
            return Buffer.from(sig).toString('hex');
          });
          respond({ type: 'signature', requestId: msg.requestId, sig: '0x' + sigHex });
        } catch (e) {
          respond({ type: 'sign_fail', requestId: msg.requestId, error: e.message });
        }
        break;
      }

      case 'sign_intent': {
        // P0-4: value-bearing asset-intent signing channel. The payload IS
        // the signed content (self-describing, amount embedded), so the
        // worker extracts the amount from what it is about to sign — not from
        // a separate parent-supplied field. A compromised parent therefore
        // cannot lie about the amount: the amount in the policy check and the
        // amount in the signed content are the same object. This closes the
        // amount-hash unlinkability limitation of the legacy 'sign' channel.
        if (!sharded) {
          respond({ type: 'sign_fail', requestId: msg.requestId, error: 'Not initialized' });
          return;
        }
        resetIdleTimer();

        const extraction = extractIntentAmount(msg.payload);
        if (extraction.error) {
          respond({ type: 'sign_fail', requestId: msg.requestId, error: extraction.error });
          return;
        }
        const amount = extraction.amount;
        const payloadStr = JSON.stringify(msg.payload);
        if (Buffer.byteLength(payloadStr, 'utf8') > SIGN_MESSAGE_MAX_BYTES) {
          respond({ type: 'sign_fail', requestId: msg.requestId, error: `Payload exceeds ${SIGN_MESSAGE_MAX_BYTES} bytes` });
          return;
        }

        // Enforce spend policy (if configured) against the amount INSIDE the
        // signed payload. Fail closed when the policy exists.
        if (policy.type) {
          const result = checkSpendAllowedTiered(policy, { amount });
          if (!result.allowed) {
            respond({ type: 'sign_fail', requestId: msg.requestId, error: result.reason || 'Policy denied' });
            return;
          }
          if (result.tier === 'medium-timelock') {
            respond({ type: 'sign_timelock', requestId: msg.requestId, timelockMs: result.timelockMs, scheduledAt: result.scheduledAt });
            return;
          }
        }

        try {
          const sigHex = sharded.use(pk => {
            const sig = signSync(payloadStr, pk);
            return Buffer.from(sig).toString('hex');
          });
          respond({ type: 'signature', requestId: msg.requestId, sig: '0x' + sigHex });
        } catch (e) {
          respond({ type: 'sign_fail', requestId: msg.requestId, error: e.message });
        }
        break;
      }

      case 'sign_message': {
        // Policy-less metadata signing channel (P0-3). NON-VALUE-BEARING:
        // task claim/submit/verify/publish, forum actions, protocol
        // bookkeeping. No spend policy applies and no amount is required —
        // the signed string is the message itself, so verifiers check
        // verify(message, sig, publicKey) exactly as for wallet.sign(message).
        // Value-bearing signing MUST go through 'sign' (policy + amount).
        //
        // ENFORCEMENT (cross-validation fix): a compromised parent could send
        // a value-bearing hash (e.g. hashAssetIntent's '0x'+64-hex output)
        // through this policy-less channel to bypass the worker-side spend
        // policy entirely. The worker — the layer that survives parent
        // compromise — therefore REFUSES hash-shaped messages. Metadata
        // payloads in this protocol are JSON strings, so the false-positive
        // risk is nil.
        if (!sharded) {
          respond({ type: 'sign_fail', requestId: msg.requestId, error: 'Not initialized' });
          return;
        }
        resetIdleTimer();

        const message = msg.message;
        if (!message || typeof message !== 'string' || message.length === 0) {
          respond({ type: 'sign_fail', requestId: msg.requestId, error: 'Invalid message (must be non-empty string)' });
          return;
        }
        if (HASH_SHAPED_RE.test(message)) {
          respond({
            type: 'sign_fail',
            requestId: msg.requestId,
            error: 'Metadata channel refuses hash-shaped messages — value-bearing hashes must go through sign() with policy (INV-002)',
          });
          return;
        }
        // P0-4 cross-validation: the on-chain verifier (verifyAgentAssetSignature)
        // accepts signatures over JSON payloads carrying type=agent_asset_intent.
        // A compromised parent could serialize such a payload as a string and
        // route it through this policy-less channel to obtain a policy-free
        // signature that the verifier accepts end-to-end (PoC-confirmed). The
        // worker — the layer that survives parent compromise — must refuse the
        // exact shape the P0-4 verification contract trusts. Metadata payloads
        // never carry this type marker, so there are no false positives.
        let parsed;
        try { parsed = JSON.parse(message); } catch { parsed = null; }
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)
            && parsed.type === 'agent_asset_intent') {
          respond({
            type: 'sign_fail',
            requestId: msg.requestId,
            error: 'Metadata channel refuses asset-intent payloads — value-bearing intents must go through sign_intent() with policy (INV-002/P0-4)',
          });
          return;
        }
        if (Buffer.byteLength(message, 'utf8') > SIGN_MESSAGE_MAX_BYTES) {
          respond({ type: 'sign_fail', requestId: msg.requestId, error: `Message exceeds ${SIGN_MESSAGE_MAX_BYTES} bytes` });
          return;
        }

        try {
          const sigHex = sharded.use(pk => {
            const sig = signSync(message, pk);
            return Buffer.from(sig).toString('hex');
          });
          respond({ type: 'signature', requestId: msg.requestId, sig: '0x' + sigHex });
        } catch (e) {
          respond({ type: 'sign_fail', requestId: msg.requestId, error: e.message });
        }
        break;
      }

      case 'ping': {
        respond({ type: 'pong', requestId: msg.requestId });
        resetIdleTimer();
        break;
      }

      case 'exit': {
        respond({ type: 'exiting', reason: 'parent_request' });
        setTimeout(() => process.exit(0), 50);
        break;
      }

      default: {
        respond({ type: 'sign_fail', requestId: msg.requestId, error: `Unknown message type: ${msg.type}` });
      }
    }
  } catch (e) {
    respond({ type: 'sign_fail', requestId: msg.requestId, error: e.message });
  }
}

// ─── Read loop: stdin → JSON-line → handleMessage ────────────────────────
// SECURITY: cap the pending input buffer. A compromised parent could
// otherwise stream unbounded bytes (never a newline) and OOM the worker,
// forcing it into swap where the sharded key could be scraped.
const MAX_LINE_BYTES = 1024 * 1024; // 1 MiB per message

// Metadata-channel guards (keep in sync with SIGN_MESSAGE_MAX_BYTES in signer.js).
// A sha256-sized hex string — with or without the 0x prefix — is the exact
// shape of a transaction/intent hash and is refused on sign_message.
const HASH_SHAPED_RE = /^(?:0x)?[0-9a-fA-F]{64}$/;
const SIGN_MESSAGE_MAX_BYTES = 64 * 1024;
let inputBuffer = '';

/**
 * P0-4: extract + validate the amount from an asset-intent payload.
 *
 * The amount is read from the payload the worker is ABOUT TO SIGN — not from
 * a separate parent-supplied field — so the amount and the signed content are
 * structurally bound. This closes the amount-hash unlinkability limitation of
 * the legacy 'sign' channel (see KNOWN ARCHITECTURAL LIMITATION in signer.js).
 *
 * @param {object} payload - canonical agent asset intent
 * @returns {{ amount?: string, error?: string }}
 */
function extractIntentAmount(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { error: 'Invalid intent payload (must be an object)' };
  }
  if (payload.type !== 'agent_asset_intent') {
    return { error: 'Invalid intent payload (missing type=agent_asset_intent)' };
  }
  const amount = payload.amount;
  if (amount === undefined || amount === null || String(amount).trim() === '') {
    return { error: 'Intent payload carries no amount (fail-closed)' };
  }
  // Reject malformed amounts ('abc', negative, empty) rather than letting
  // BigInt() throw or silently coerce. Mirrors checkSpendAllowed's guards.
  let amountBig;
  try {
    const s = String(amount).trim();
    if (s === '') throw new Error('empty');
    amountBig = BigInt(s);
    if (amountBig < 0n) throw new Error('negative');
  } catch {
    return { error: `Invalid amount in intent payload: ${amount}` };
  }
  return { amount: String(amountBig) };
}

process.stdin.on('data', (chunk) => {
  inputBuffer += chunk.toString();
  if (Buffer.byteLength(inputBuffer, 'utf8') > MAX_LINE_BYTES) {
    respond({ type: 'sign_fail', error: `Message exceeds ${MAX_LINE_BYTES} bytes` });
    process.exit(1);
  }
  const lines = inputBuffer.split('\n');
  inputBuffer = lines.pop(); // Keep incomplete line in buffer.
  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      handleMessage(JSON.parse(line));
    } catch (e) {
      respond({ type: 'sign_fail', error: `Parse error: ${e.message}` });
    }
  }
});

process.stdin.on('end', () => {
  // Parent closed stdin — clean up and exit.
  if (sharded) { sharded.destroy(); sharded = null; }
  process.exit(0);
});

// ─── Signal handling ─────────────────────────────────────────────────────
process.on('SIGTERM', () => {
  if (sharded) { sharded.destroy(); sharded = null; }
  process.exit(0);
});
process.on('SIGINT', () => {
  if (sharded) { sharded.destroy(); sharded = null; }
  process.exit(0);
});