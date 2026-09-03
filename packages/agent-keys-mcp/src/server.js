#!/usr/bin/env node
/**
 * aegis-vault-mcp — MCP Server
 *
 * Exposes Aegis Vault agent-keys as MCP tools for Claude Desktop, Cursor,
 * LangGraph, and any MCP-compatible host.
 *
 * Usage:
 *   npx aegis-vault-mcp
 *
 * Environment variables:
 *   KEY_ENVELOPE   — JSON-serialized key envelope (or --envelope-file)
 *   KEY_PASSWORD   — password to decrypt the envelope
 *
 * Protocol: JSON-RPC 2.0 over stdio (MCP standard transport)
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import {
  getPQCInfo,
  signSync,
  verify,
  generateKeyPair,
  encryptPrivateKey,
  isValidEnvelope,
  decryptPrivateKey,
  createSessionKey,
  checkSessionAccess,
  checkSpendAllowedTiered,
  resolveTier,
  ShardedSecret,
  disableCoreDumps,
} from 'aegis-vault';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// ─── Bootstrap ──────────────────────────────────────────────────────────
disableCoreDumps();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = path.resolve(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(PKG_ROOT, 'package.json'), 'utf-8'));

// Base spend policy for the sign tool: no per-tx/daily ceilings (operator
// scopes those via session keys), but three-tier gradient authorization is
// ALWAYS enforced — small auto-signs, medium is timelocked, large requires
// human approval. Tier thresholds come from takeover.js defaults (10/100).
const SIGN_POLICY = { type: 'limit', maxPerTx: '0', maxDaily: '0' };

// ─── State ──────────────────────────────────────────────────────────────
let sharded = null;          // ShardedSecret (for direct sign tool)

// ─── Helpers ────────────────────────────────────────────────────────────

/** Initialize the key from env vars or command-line args. */
function initKeyFromEnv() {
  const env = process.env.KEY_ENVELOPE;
  const pass = process.env.KEY_PASSWORD;
  if (!env || !pass) {
    console.error('[mcp] KEY_ENVELOPE and KEY_PASSWORD must be set');
    return false;
  }
  try {
    const parsed = JSON.parse(env);
    // Accept both the bare envelope and the full generate-key output
    // ({ publicKey, envelope }) — unwrap the latter.
    const envelope = parsed.envelope && parsed.envelope.cipher ? parsed.envelope : parsed;
    if (!isValidEnvelope(envelope)) {
      console.error('[mcp] Invalid key envelope');
      return false;
    }
    const privateKey = decryptPrivateKey(envelope, pass);
    sharded = new ShardedSecret(privateKey);
    return true;
  } catch (err) {
    console.error('[mcp] Failed to init key:', err.message);
    return false;
  }
}

// ─── Tool Definitions ───────────────────────────────────────────────────

const TOOLS = {
  sign: {
    name: 'sign',
    description: 'Sign a hash with the agent key (Dilithium2). Returns 0x-prefixed hex signature.',
    inputSchema: {
      type: 'object',
      properties: {
        hash: { type: 'string', description: 'Hex hash to sign (0x-prefixed)' },
        amount: { type: 'string', description: 'Transaction amount (for policy check)' },
      },
      required: ['hash'],
    },
  },
  verify: {
    name: 'verify',
    description: 'Verify a Dilithium2 signature against a message and public key.',
    inputSchema: {
      type: 'object',
      properties: {
        message: { type: 'string', description: 'Original message (hex)' },
        signature: { type: 'string', description: 'Signature (hex)' },
        publicKey: { type: 'string', description: 'Public key (hex)' },
      },
      required: ['message', 'signature', 'publicKey'],
    },
  },
  generate_key: {
    name: 'generate_key',
    description: 'Generate a new Dilithium2 key pair. Returns publicKey and encrypted privateKey envelope.',
    inputSchema: {
      type: 'object',
      properties: {
        password: { type: 'string', description: 'Password to encrypt the private key' },
      },
      required: ['password'],
    },
  },
  create_session: {
    name: 'create_session',
    description: 'Create a session key with five-dimensional permission scoping.',
    inputSchema: {
      type: 'object',
      properties: {
        agentId: { type: 'string', description: 'Agent identifier' },
        allowedContracts: { type: 'array', items: { type: 'string' }, description: 'Contract whitelist' },
        allowedMethods: { type: 'array', items: { type: 'string' }, description: 'Method whitelist' },
        allowedChains: { type: 'array', items: { type: 'string' }, description: 'Chain whitelist' },
        maxPerTx: { type: 'string', description: 'Max amount per transaction' },
        maxDaily: { type: 'string', description: 'Max daily total' },
        ttl: { type: 'number', description: 'Time-to-live in ms (default 24h)' },
      },
      required: ['agentId'],
    },
  },
  check_session: {
    name: 'check_session',
    description: 'Check whether a session key authorizes a specific action.',
    inputSchema: {
      type: 'object',
      properties: {
        session: { type: 'object', description: 'Session key object' },
        contract: { type: 'string', description: 'Contract address to check' },
        method: { type: 'string', description: 'Method to call' },
        chain: { type: 'string', description: 'Chain identifier' },
        amount: { type: 'string', description: 'Transaction amount' },
      },
      required: ['session'],
    },
  },
  pqc_info: {
    name: 'pqc_info',
    description: 'Get PQC algorithm metadata and benchmark comparison.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  check_tier: {
    name: 'check_tier',
    description: 'Check which authorization tier an amount falls into (small-auto, medium-timelock, large-require-approval).',
    inputSchema: {
      type: 'object',
      properties: {
        amount: { type: 'string', description: 'Transaction amount' },
      },
      required: ['amount'],
    },
  },
};

// ─── Tool Handlers ──────────────────────────────────────────────────────

const HANDLERS = {
  async sign(args) {
    if (!sharded) {
      if (!initKeyFromEnv()) {
        return { content: [{ type: 'text', text: 'Key not initialized. Set KEY_ENVELOPE and KEY_PASSWORD.' }], isError: true };
      }
    }
    const { hash: hashHex, amount } = args;
    if (typeof hashHex !== 'string' || !/^0x[0-9a-fA-F]+$/.test(hashHex)) {
      return { content: [{ type: 'text', text: 'Invalid hash: must be 0x-hex string' }], isError: true };
    }
    // Tiered authorization: when an amount is declared, three-tier gradient
    // authorization applies. Medium tier is NOT signed immediately — the 24h
    // time-lock (revocable by humans) must elapse first, mirroring the
    // signer-worker's sign_timelock behavior.
    if (amount !== undefined && amount !== null) {
      const tierCheck = checkSpendAllowedTiered(SIGN_POLICY, { amount });
      if (!tierCheck.allowed) {
        return { content: [{ type: 'text', text: `Policy denied: ${tierCheck.reason}` }], isError: true };
      }
      if (tierCheck.timelockMs) {
        return {
          content: [{
            type: 'text',
            text: `Timelocked: amount is in medium tier. Signature withheld until ${new Date(tierCheck.scheduledAt).toISOString()} (24h revocation window). Re-submit after the timelock elapses.`,
          }],
          isError: true,
        };
      }
    }
    const sigHex = sharded.use(pk => signSync(hashHex, pk).toString('hex'));
    return { content: [{ type: 'text', text: `0x${sigHex}` }] };
  },

  async verify(args) {
    const { message, signature, publicKey } = args;
    const msgBuf = Buffer.from(message, 'hex');
    const sigBuf = Buffer.from(signature, 'hex');
    const pkBuf = Buffer.from(publicKey, 'hex');
    const result = await verify(msgBuf, sigBuf, pkBuf);
    return { content: [{ type: 'text', text: String(result) }] };
  },

  async generate_key(args) {
    const { password } = args;
    const { publicKey, privateKey } = await generateKeyPair();
    const envelope = encryptPrivateKey(privateKey, password, { publicKey: publicKey.toString('hex') });
    return {
      content: [
        { type: 'text', text: JSON.stringify({ publicKey: publicKey.toString('hex'), envelope }, null, 2) },
      ],
    };
  },

  async create_session(args) {
    const { agentId, allowedContracts, allowedMethods, allowedChains, maxPerTx, maxDaily, ttl } = args;
    if (!sharded) {
      if (!initKeyFromEnv()) {
        return { content: [{ type: 'text', text: 'Key not initialized' }], isError: true };
      }
    }
    const session = sharded.use(pk => {
      return createSessionKey(pk, {
        agentId,
        allowedContracts: allowedContracts || [],
        allowedMethods: allowedMethods || [],
        allowedChains: allowedChains || [],
        maxPerTx: maxPerTx || '0',
        maxDaily: maxDaily || '0',
        ttl: ttl || 24 * 60 * 60 * 1000,
      });
    });
    return { content: [{ type: 'text', text: JSON.stringify(session, null, 2) }] };
  },

  async check_session(args) {
    const { session, contract, method, chain, amount } = args;
    const result = checkSessionAccess(session, { contract, method, chain, amount });
    return { content: [{ type: 'text', text: JSON.stringify(result) }] };
  },

  async pqc_info() {
    const info = getPQCInfo();
    return { content: [{ type: 'text', text: JSON.stringify(info, null, 2) }] };
  },

  async check_tier(args) {
    const { amount } = args;
    const tier = resolveTier(amount);
    return { content: [{ type: 'text', text: JSON.stringify(tier, null, 2) }] };
  },
};

// ─── Server Setup ───────────────────────────────────────────────────────

const server = new Server(
  { name: 'aegis-vault', version: pkg.version },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: Object.values(TOOLS),
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const tool = TOOLS[request.params.name];
  if (!tool) {
    return { content: [{ type: 'text', text: `Unknown tool: ${request.params.name}` }], isError: true };
  }
  try {
    const handler = HANDLERS[request.params.name];
    if (!handler) {
      return { content: [{ type: 'text', text: `No handler for: ${request.params.name}` }], isError: true };
    }
    return await handler(request.params.arguments || {});
  } catch (err) {
    return { content: [{ type: 'text', text: `Error: ${err.message}` }], isError: true };
  }
});

// ─── Start ──────────────────────────────────────────────────────────────

async function main() {
  // Try to init key from env at startup
  initKeyFromEnv();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('[mcp] aegis-vault MCP server running on stdio');
}

main().catch((err) => {
  console.error('[mcp] Fatal error:', err);
  process.exit(1);
});