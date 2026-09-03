#!/usr/bin/env node
/**
 * Aegis Vault — release registry smoke test
 *
 * Installs the ACTUAL PUBLISHED packages from the npm registry into a fresh
 * temp dir and verifies the critical security flows end-to-end across ALL SIX
 * published packages:
 *
 *   1. agent-keys     : PQCWallet present (transitive, but verified directly)
 *   2. agent-sdk      : createAgentIdentity → signAgentAsset → verifyAgentAssetSignature
 *   3. chain-eth      : createSmartAccount → executeFromAgent (INV-005/006/007 matrix)
 *   4. chain-sol      : deriveSolWalletFromPQC → signMessage → verifyMessage round-trip
 *   5. chain-adapters : deriveAgentFingerprint / deriveChainAddresses produce stable output
 *   6. agent-mcp      : module loads (stdio MCP server, no named exports)
 *
 * Usage:
 *   node scripts/release-smoke.mjs                                # latest of each pkg
 *   node scripts/release-smoke.mjs 0.5.0 0.3.0 0.3.0 0.2.2 0.2.2 0.3.0
 *       # keys sdk eth sol adapters mcp — versions pinned explicitly
 *   SMOKE_KEEP=1 node scripts/release-smoke.mjs                   # keep temp dir on failure
 *
 * Exit code 0 = PASS, 1 = FAIL. Mirrors the post-publish CI job in
 * .github/workflows/npm-publish.yml.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

const PACKAGES = {
  keys: 'aegis-vault',
  sdk: 'aegis-agent-sdk',
  eth: 'aegis-chain-eth',
  sol: 'aegis-chain-sol',
  adapters: 'aegis-chain-adapters',
  mcp: 'aegis-agent-mcp',
};
// CLI args are 6 explicit versions (keys sdk eth sol adapters mcp); default latest.
const [keysVer, sdkVer, ethVer, solVer, adaptersVer, mcpVer] = process.argv.slice(2).concat(
  Array(Math.max(0, 6 - (process.argv.length - 2))).fill('latest')
);

function sh(cmd, args, cwd) {
  return execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], shell: true });
}
// `npm` resolves to npm.cmd on Windows; shell:true lets cmd.exe locate it.

// ─── Fresh install from registry ─────────────────────────────────────────
const dir = mkdtempSync(join(tmpdir(), 'ng-smoke-'));
const keep = process.env.SMOKE_KEEP === '1';
console.log(`[setup] fresh install dir: ${dir}`);
console.log(`[setup] pinned versions: keys=${keysVer} sdk=${sdkVer} eth=${ethVer} sol=${solVer} adapters=${adaptersVer} mcp=${mcpVer}`);

try {
  sh('npm', ['init', '-y'], dir);
  sh('npm', ['install', '--no-audit', '--no-fund', '--no-save',
    `${PACKAGES.keys}@${keysVer}`, `${PACKAGES.sdk}@${sdkVer}`, `${PACKAGES.eth}@${ethVer}`,
    `${PACKAGES.sol}@${solVer}`, `${PACKAGES.adapters}@${adaptersVer}`, `${PACKAGES.mcp}@${mcpVer}`], dir);

  // Resolve installed package versions from disk for the pin report
  // (exports map blocks importing ./package.json subpath).
  const readPkg = (name) => {
    try {
      const p = join(dir, 'node_modules', name, 'package.json');
      return JSON.parse(readFileSync(p, 'utf8')).version;
    } catch {
      return 'n/a';
    }
  };

  console.log('[0] installed versions:');
  for (const [k, name] of Object.entries(PACKAGES)) console.log(`    ${k.padEnd(9)} ${name}: ${readPkg(name)}`);

  // ESM packages (agent-mcp has top-level await) → dynamic import from temp dir.
  // require.resolve returns a Windows `c:\` path; import() needs a file:// URL.
  const load = (spec) => import(pathToFileURL(require.resolve(spec, { paths: [dir] })));
  const keys = await load(PACKAGES.keys);
  const sdk = await load(PACKAGES.sdk);
  const eth = await load(PACKAGES.eth);
  const sol = await load(PACKAGES.sol);
  const adapters = await load(PACKAGES.adapters);
  const mcp = await load(PACKAGES.mcp);

  assert.ok(keys.PQCWallet, 'agent-keys missing PQCWallet');

  // ─── 1. agent-sdk: identity + asset signing + on-chain verifier ────────
  const identity = await sdk.createAgentIdentity({ password: 'smoke-secret-123' });
  assert.ok(identity.address.startsWith('ng1'), 'identity address must start ng1');
  assert.ok(!('privateKey' in identity), 'identity must not expose private key');

  const wallet = sdk.recoverAgentIdentity(identity.envelope, 'smoke-secret-123');
  assert.equal(wallet.address, identity.address, 'recovered wallet must match identity');

  const issuer = await keys.PQCWallet.generate();
  const session = keys.createSessionKey(issuer.privateKey, {
    agentId: 'smoke-agent',
    allowedChains: ['ethereum'],
    allowedAssets: ['USDC'],
    allowedMethods: ['transfer'],
    maxPerTx: '100',
    maxDaily: '500',
    ttl: 60 * 60 * 1000,
  });

  const intent = {
    action: 'transfer', chain: 'ethereum', asset: 'USDC', amount: '25',
    recipient: '0xSmoke', contract: '0xContract', method: 'transfer', nonce: '1',
  };
  const sig = await sdk.signAgentAsset({ wallet, session, issuerPublicKey: issuer.publicKey, intent });
  assert.ok(typeof sig === 'string' && sig.length > 0, 'signAgentAsset must return a signature');

  const canonical = sdk.canonicalizeAssetIntent(session, intent);
  const verified = await sdk.verifyAgentAssetSignature({ payload: canonical, signature: sig, publicKey: identity.publicKeyHex });
  assert.equal(verified.valid, true, `verifier must accept valid signature: ${verified.reason}`);
  assert.equal(verified.amount, '25', 'verifier must decode amount=25');
  console.log('[1] agent-sdk: identity + signAgentAsset + verifyAgentAssetSignature OK');

  // ─── 2. chain-eth: Smart Account on-chain hard policy ──────────────────
  const acct = eth.createSmartAccount({
    owner: '0xOwner',
    emergencyKey: '0xEmergency',
    policy: { type: 'limit', maxPerTx: '100', maxDaily: '500' },
  });
  const reg = acct.registerSession({
    by: '0xOwner',
    sessionId: 'smoke-s1',
    agentId: 'smoke-agent',
    agentPublicKey: identity.publicKeyHex,
    issuedAt: session.issuedAt,
    expiresAt: session.expiresAt,
    whitelist: { allowedChains: ['ethereum'], allowedAssets: ['USDC'], allowedContracts: ['0xContract'], allowedMethods: ['transfer'], allowedRecipients: ['0xSmoke'] },
    maxPerTx: '100',
    maxDaily: '500',
  });
  assert.equal(reg.ok, true, reg.reason);

  const exec = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '25', sessionId: 'smoke-s1', nonce: 1 });
  assert.equal(exec.ok, true, `executeFromAgent must accept: ${exec.reason}`);
  assert.equal(exec.amount, '25');
  assert.ok(exec.txId.startsWith('0x'), 'must return 0x txId');

  // INV-007: replay with same nonce must fail.
  const replay = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '25', sessionId: 'smoke-s1', nonce: 1 });
  assert.equal(replay.ok, false, 'replay with same nonce must be rejected');
  assert.match(replay.reason, /replay/i);

  // INV-007: amount drift must fail (new signed intent, divergent claim).
  const driftIntent = { ...intent, nonce: '2' };
  const driftCanonical = sdk.canonicalizeAssetIntent(session, driftIntent);
  const driftSig = await wallet.sign(JSON.stringify(driftCanonical));
  const drift = await acct.executeFromAgent({ payload: driftCanonical, signature: driftSig, claimedAmount: '999', sessionId: 'smoke-s1', nonce: 2 });
  assert.equal(drift.ok, false, 'claimed amount drift must be rejected');
  assert.match(drift.reason, /amount mismatch/i);

  // INV-005: self-escalation even if signed must fail.
  const escIntent = { ...intent, action: 'addOwner', method: 'addOwner', amount: '5' };
  const escCanonical = sdk.canonicalizeAssetIntent(session, escIntent);
  const escSig = await wallet.sign(JSON.stringify(escCanonical));
  const esc = await acct.executeFromAgent({ payload: escCanonical, signature: escSig, claimedAmount: '5', sessionId: 'smoke-s1', nonce: 3 });
  assert.equal(esc.ok, false, 'self-escalation must be rejected on-chain');
  assert.match(esc.reason, /self-escalation/i);

  // INV-006: emergency is brake-only.
  assert.equal(acct.pause({ by: '0xEmergency' }).ok, true, 'emergency can pause');
  const paused = await acct.executeFromAgent({ payload: canonical, signature: sig, claimedAmount: '25', sessionId: 'smoke-s1', nonce: 4 });
  assert.equal(paused.ok, false, 'paused account must reject executions');
  assert.equal(acct.resume({ by: '0xEmergency' }).ok, false, 'emergency cannot resume');
  assert.equal(acct.resume({ by: '0xOwner' }).ok, true, 'owner can resume');
  console.log('[2] chain-eth: Smart Account executeFromAgent + INV-005/006/007 OK');

  // ─── 3. chain-sol: key derivation + sign/verify round-trip ─────────────
  // deriveSolWalletFromPQC takes the PQC PRIVATE key (Buffer); sign/verify
  // take ed25519 keys as Buffer (hex strings would be utf8-encoded).
  const solWallet = sol.deriveSolWalletFromPQC(issuer.privateKey);
  assert.ok(solWallet && solWallet.address, 'chain-sol must derive a Solana wallet from PQC private key');
  const solMsg = JSON.stringify({ action: 'claim', chain: 'solana', agent: identity.address });
  const solSig = sol.signMessage(solMsg, Buffer.from(solWallet.privateKeyHex, 'hex'));
  assert.ok(solSig, 'chain-sol signMessage must produce a signature');
  const solOk = sol.verifyMessage(solMsg, solSig, Buffer.from(solWallet.publicKeyHex, 'hex'));
  assert.equal(solOk, true, 'chain-sol verifyMessage must accept its own signature');
  console.log(`[3] chain-sol: deriveSolWalletFromPQC + sign/verify round-trip OK (${solWallet.address})`);

  // ─── 4. chain-adapters: fingerprint / multi-chain address derivation ───
  // Functions take PQC key Buffers, not hex strings.
  const fp = adapters.deriveAgentFingerprint(issuer.publicKey);
  assert.ok(fp && typeof fp === 'string' && fp.length > 0, 'deriveAgentFingerprint must return a stable digest');
  const addr = adapters.deriveChainAddresses(issuer.publicKey, issuer.privateKey);
  assert.ok(addr && (addr.eth || addr.sol), 'deriveChainAddresses must derive at least one chain address');
  const stable = adapters.deriveAgentFingerprint(issuer.publicKey);
  assert.equal(stable, fp, 'fingerprint must be deterministic');
  console.log(`[4] chain-adapters: deriveAgentFingerprint + deriveChainAddresses OK (${addr.nexus})`);

  // ─── 5. agent-mcp: module loads without error ──────────────────────────
  const mcpKeys = Object.keys(mcp);
  console.log('[5] agent-mcp loaded; namespace keys:', JSON.stringify(mcpKeys));
  console.log('    (stdin/stdout MCP server — no named exports expected)');

  console.log('\nSMOKE PASS — all six published packages verified end-to-end');
  process.exitCode = 0;
  // agent-mcp opens a stdio listener on import, keeping the event loop alive;
  // clean up the temp dir then force-exit so the script terminates promptly
  // with its status code (finally won't run after process.exit).
  if (!keep) rmSync(dir, { recursive: true, force: true });
  process.exit(0);
} catch (err) {
  console.error('\nSMOKE FAIL:', err && err.message ? err.message : err);
  if (err && err.stdout) console.error('stdout:', err.stdout);
  if (err && err.stderr) console.error('stderr:', String(err.stderr).slice(0, 2000));
  process.exitCode = 1;
} finally {
  if (!keep) {
    rmSync(dir, { recursive: true, force: true });
  } else if (process.exitCode !== 0) {
    console.log(`[cleanup] keeping temp dir for inspection: ${dir}`);
  }
}
