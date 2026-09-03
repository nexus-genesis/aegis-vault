#!/usr/bin/env node
/**
 * aegis-vault-cli — Command-line interface
 *
 * Usage:
 *   aegis-vault generate-key <password>
 *   aegis-vault sign <hash> [--amount <amount>]
 *   aegis-vault verify <message-hex> <signature-hex> <public-key-hex>
 *   aegis-vault session create <agent-id> [--ttl <ms>] [--max-per-tx <n>]
 *   aegis-vault session check <session-json> [--contract <addr>]
 *   aegis-vault info
 *   aegis-vault tier <amount>
 *   aegis-vault benchmark
 *   aegis-vault serve                             # Start signer daemon (stdio)
 *
 * Options:
 *   --envelope <file>   Key envelope file (required for sign, session, serve)
 *   --password <pass>   Password to decrypt envelope
 *   --help, -h          Show this help
 */

import {
  generateKeyPair,
  signSync,
  verify,
  getPQCInfo,
  hash,
  encryptPrivateKey,
  decryptPrivateKey,
  isValidEnvelope,
  createSessionKey,
  checkSessionAccess,
  checkSpendAllowedTiered,
  resolveTier,
  ShardedSecret,
  disableCoreDumps,
  spawnSigner,
} from 'aegis-vault';
import fs from 'node:fs';
import path from 'node:path';

disableCoreDumps();

// Base spend policy for the sign command: no per-tx/daily ceilings (operator
// scopes those via session keys), but three-tier gradient authorization is
// ALWAYS enforced — small auto-signs, medium is timelocked, large requires
// human approval. Tier thresholds come from takeover.js defaults (10/100).
const SIGN_POLICY = { type: 'limit', maxPerTx: '0', maxDaily: '0' };

// ─── Helpers ────────────────────────────────────────────────────────────

function loadKey(envelopeFile, password) {
  if (!envelopeFile) throw new Error('--envelope is required');
  if (!password) throw new Error('--password is required');
  const raw = fs.readFileSync(envelopeFile, 'utf-8');
  const parsed = JSON.parse(raw);
  // Accept both the bare envelope and the full generate-key output
  // ({ publicKey, envelope }) — unwrap the latter.
  const envelope = parsed.envelope && parsed.envelope.cipher ? parsed.envelope : parsed;
  if (!isValidEnvelope(envelope)) throw new Error('Invalid envelope file');
  const privateKey = decryptPrivateKey(envelope, password);
  return new ShardedSecret(privateKey);
}

function print(obj) {
  console.log(JSON.stringify(obj, null, 2));
}

// ─── Commands ───────────────────────────────────────────────────────────

const COMMANDS = {
  async 'generate-key'([password]) {
    if (!password) throw new Error('Usage: aegis-vault generate-key <password>');
    const { publicKey, privateKey } = await generateKeyPair();
    const envelope = encryptPrivateKey(privateKey, password, { publicKey: publicKey.toString('hex') });
    print({ publicKey: publicKey.toString('hex'), envelope });
  },

  async 'sign'([hashHex], { envelope, password, amount }) {
    if (typeof hashHex !== 'string' || !/^0x[0-9a-fA-F]+$/.test(hashHex)) {
      throw new Error('Invalid hash: must be a 0x-hex string');
    }
    const sharded = loadKey(envelope, password);
    if (amount !== undefined) {
      // Tiered authorization: medium tier (10-100) is NOT signed immediately —
      // the 24h time-lock must elapse first; large tier requires human approval.
      const check = checkSpendAllowedTiered(SIGN_POLICY, { amount });
      if (!check.allowed) {
        console.error(`Policy denied: ${check.reason}`);
        process.exit(1);
      }
      if (check.timelockMs) {
        console.error(`Timelocked: amount is in medium tier. Signature withheld until ${new Date(check.scheduledAt).toISOString()} (24h revocation window).`);
        process.exit(1);
      }
    }
    const sigHex = sharded.use(pk => signSync(hashHex, pk).toString('hex'));
    print({ signature: `0x${sigHex}` });
  },

  async 'verify'([message, signature, publicKey]) {
    if (!message || !signature || !publicKey) {
      throw new Error('Usage: aegis-vault verify <message-hex> <signature-hex> <public-key-hex>');
    }
    const result = await verify(
      Buffer.from(message, 'hex'),
      Buffer.from(signature, 'hex'),
      Buffer.from(publicKey, 'hex')
    );
    print({ valid: result });
  },

  async 'session'([sub, ...args], opts) {
    if (!sub) throw new Error('Usage: aegis-vault session <create|check> [...]');
    switch (sub) {
      case 'create': {
        const [agentId] = args;
        if (!agentId) throw new Error('Usage: aegis-vault session create <agent-id>');
        const sharded = loadKey(opts.envelope, opts.password);
        const session = sharded.use(pk => createSessionKey(pk, {
          agentId,
          ttl: parseInt(opts.ttl) || (24 * 60 * 60 * 1000),
          maxPerTx: opts['max-per-tx'] || '0',
          maxDaily: opts['max-daily'] || '0',
          allowedContracts: opts['allow-contract'] ? opts['allow-contract'].split(',') : [],
          allowedMethods: opts['allow-method'] ? opts['allow-method'].split(',') : [],
          allowedChains: opts['allow-chain'] ? opts['allow-chain'].split(',') : [],
        }));
        print(session);
        break;
      }
      case 'check': {
        const [sessionJson] = args;
        if (!sessionJson) throw new Error('Usage: aegis-vault session check <session-json>');
        const session = JSON.parse(sessionJson);
        const result = checkSessionAccess(session, {
          contract: opts.contract,
          method: opts.method,
          chain: opts.chain,
          amount: opts.amount,
        });
        print(result);
        break;
      }
      default:
        throw new Error(`Unknown subcommand: ${sub}`);
    }
  },

  async 'info'() {
    print(getPQCInfo());
  },

  async 'tier'([amount]) {
    if (!amount) throw new Error('Usage: aegis-vault tier <amount>');
    const tier = resolveTier(amount);
    print(tier);
  },

  async 'benchmark'() {
    console.log('PQC benchmark lives in the agent-keys package:');
    console.log('  cd packages/agent-keys && node bench/pqc-benchmark.js');
  },

  async 'serve'([], opts) {
    // Envelope/password resolution: CLI flags first, then env vars (Docker/
    // Kubernetes friendly: KEY_ENVELOPE_FILE + KEY_PASSWORD + IDLE_TIMEOUT_MS).
    const envelopeFile = opts.envelope || process.env.KEY_ENVELOPE_FILE || '/app/key.json';
    const password = opts.password || process.env.KEY_PASSWORD;
    const idleTimeoutMs = opts['idle-timeout']
      ? parseInt(opts['idle-timeout'], 10)
      : (process.env.IDLE_TIMEOUT_MS ? parseInt(process.env.IDLE_TIMEOUT_MS, 10) : undefined);

    if (!fs.existsSync(envelopeFile)) {
      throw new Error(`Key envelope file not found: ${envelopeFile} (use --envelope or KEY_ENVELOPE_FILE)`);
    }
    if (!password) {
      throw new Error('Password required (--password or KEY_PASSWORD env)');
    }

    const signer = await spawnSigner({
      // Accept both the bare envelope and the full generate-key output
      // ({ publicKey, envelope }) — unwrap the latter.
      envelope: (() => {
        const parsed = JSON.parse(fs.readFileSync(envelopeFile, 'utf-8'));
        return parsed.envelope && parsed.envelope.cipher ? parsed.envelope : parsed;
      })(),
      password,
      idleTimeoutMs,
    });
    console.error(`[signer-daemon] Started (envelope: ${envelopeFile}), idle timeout: ${idleTimeoutMs ?? 'default 5min'}`);
    // Keep alive
    process.on('SIGINT', async () => {
      await signer.close();
      process.exit(0);
    });
    process.on('SIGTERM', async () => {
      await signer.close();
      process.exit(0);
    });
    // Expose signer handle globally for parent process embedding
    globalThis.__signerHandle = signer;
    await new Promise(() => {}); // park forever; killed by signal
  },
};

// ─── Main ───────────────────────────────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {};
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      const key = args[i].slice(2);
      const eqIdx = key.indexOf('=');
      if (eqIdx !== -1) {
        opts[key.slice(0, eqIdx)] = key.slice(eqIdx + 1);
      } else if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        opts[key] = args[++i];
      } else {
        opts[key] = true;
      }
    } else {
      positional.push(args[i]);
    }
  }
  return { positional, opts };
}

async function main() {
  const { positional, opts } = parseArgs();

  if (opts.help || opts.h || positional.length === 0) {
    console.log(`
aegis-vault agent-keys CLI

Usage:
  aegis-vault <command> [args...] [options]

Commands:
  generate-key <password>          Generate a new Dilithium2 key pair
  sign <hash>                      Sign a hash
  verify <msg> <sig> <pubkey>     Verify a signature
  session create <agent-id>        Create a session key
  session check <json>             Check session access
  info                             Get PQC algorithm info
  tier <amount>                    Check authorization tier
  benchmark                        Run PQC benchmark
  serve                            Start signer daemon

Options:
  --envelope <file>                Key envelope file
  --password <pass>                Password to decrypt envelope
  --amount <n>                     Transaction amount (for sign/tier)
  --ttl <ms>                       Session TTL (for session create)
  --max-per-tx <n>                 Max per transaction
  --max-daily <n>                  Max daily total
  --allow-contract <list>          Comma-separated contract whitelist
  --allow-method <list>            Comma-separated method whitelist
  --allow-chain <list>             Comma-separated chain whitelist
  --contract <addr>                Contract address (for session check)
  --method <name>                  Method name (for session check)
  --chain <name>                   Chain name (for session check)
  --idle-timeout <ms>              Idle timeout for serve daemon
  --help, -h                       Show this help
`);
    return;
  }

  const cmd = positional[0];
  const handler = COMMANDS[cmd];
  if (!handler) {
    console.error(`Unknown command: ${cmd}. Use --help for usage.`);
    process.exit(1);
  }

  try {
    await handler(positional.slice(1), opts);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

main();