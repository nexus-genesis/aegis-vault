// E2E smoke test for the Wave 3 fixes (run inside packages/agent-keys-cli)
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';

const NODE = process.execPath;
const CLI = 'src/cli.js';
let failures = 0;

function run(args, { expectFail = false } = {}) {
  try {
    const out = execFileSync(NODE, [CLI, ...args], { encoding: 'utf-8', timeout: 60000 });
    return { ok: true, out };
  } catch (err) {
    if (expectFail) return { ok: false, out: (err.stdout || '') + (err.stderr || '') };
    throw err;
  }
}

function check(name, cond, detail = '') {
  if (cond) console.log(`PASS  ${name}`);
  else { failures++; console.log(`FAIL  ${name} ${detail}`); }
}

// 1. generate-key
const gen = run(['generate-key', 'test-password-123']);
const genOut = JSON.parse(gen.out);
check('generate-key outputs {publicKey, envelope}', !!genOut.publicKey && !!genOut.envelope.cipher);
fs.writeFileSync('test-key.json', gen.out);

// 2. tier resolution (was broken: always returned large tier)
check('tier 5 => small-auto', run(['tier', '5']).out.includes('small'));
check('tier 50 => medium-timelock', run(['tier', '50']).out.includes('medium'));
check('tier 500 => large-require-approval', run(['tier', '500']).out.includes('large'));

// 3. sign without amount (pure message signing)
const hash = '0x' + 'ab'.repeat(32);
const sigNoAmt = run(['sign', hash, '--envelope', 'test-key.json', '--password', 'test-password-123']);
const sigJson = JSON.parse(sigNoAmt.out);
check('sign without amount succeeds', /^0x[0-9a-f]+$/.test(sigJson.signature));

// 4. sign with small amount => signs
const sigSmall = run(['sign', hash, '--envelope', 'test-key.json', '--password', 'test-password-123', '--amount', '5']);
check('sign small amount succeeds', /^0x[0-9a-f]+$/.test(JSON.parse(sigSmall.out).signature));

// 5. sign with medium amount => REFUSED (24h timelock) — the P0 fix
const sigMedium = run(['sign', hash, '--envelope', 'test-key.json', '--password', 'test-password-123', '--amount', '50'], { expectFail: true });
check('sign medium amount is timelocked (P0 fix)', !sigMedium.ok && /Timelocked/i.test(sigMedium.out));

// 6. sign with large amount => REFUSED
const sigLarge = run(['sign', hash, '--envelope', 'test-key.json', '--password', 'test-password-123', '--amount', '500'], { expectFail: true });
check('sign large amount denied', !sigLarge.ok && /requires human approval/i.test(sigLarge.out));

// 7. sign rejects invalid hash format
const badHash = run(['sign', 'nothex', '--envelope', 'test-key.json', '--password', 'test-password-123'], { expectFail: true });
check('sign rejects non-0x hash', !badHash.ok && /0x-hex/i.test(badHash.out));

// 8. verify round-trip
const sigHex = sigJson.signature.replace(/^0x/, '');
const msgHex = Buffer.from(hash, 'utf-8').toString('hex');
const ver = run(['verify', msgHex, sigHex, genOut.publicKey.replace(/^0x/, '')]);
check('verify round-trip', JSON.parse(ver.out).valid === true);

// 9. session create works with full generate-key file (unwrap fix)
const sess = run(['session', 'create', 'agent-e2e', '--envelope', 'test-key.json', '--password', 'test-password-123', '--max-per-tx', '100']);
const session = JSON.parse(sess.out);
check('session create unwraps envelope', session.type === 'session_key' && !!session.signature);

// 10. session check enforces maxPerTx
const ok2 = run(['session', 'check', sess.out, '--amount', '50']);
const denied = run(['session', 'check', sess.out, '--amount', '150']);
check('session check allows within maxPerTx', JSON.parse(ok2.out).allowed === true);
check('session check denies over maxPerTx', JSON.parse(denied.out).allowed === false);

fs.unlinkSync('test-key.json');
console.log(failures === 0 ? '\nALL E2E CHECKS PASSED' : `\n${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);