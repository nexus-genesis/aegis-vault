// MCP sign tool: medium-amount timelock enforcement (the P0 fix path)
import { spawn } from 'node:child_process';
import { generateKeyPair, encryptPrivateKey } from 'aegis-vault';

const { publicKey, privateKey } = await generateKeyPair();
const envelope = encryptPrivateKey(privateKey, 'mcp-test-password', { publicKey: publicKey.toString('hex') });

const proc = spawn(process.execPath, ['src/server.js'], {
  stdio: ['pipe', 'pipe', 'pipe'],
  env: {
    ...process.env,
    KEY_ENVELOPE: JSON.stringify(envelope),
    KEY_PASSWORD: 'mcp-test-password',
  },
});

let buf = '';
const pending = new Map();
let id = 0;
proc.stdout.on('data', (d) => {
  buf += d.toString();
  let idx;
  while ((idx = buf.indexOf('\n')) !== -1) {
    const line = buf.slice(0, idx);
    buf = buf.slice(idx + 1);
    if (!line.trim()) continue;
    const msg = JSON.parse(line);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  }
});

function request(method, params) {
  const msgId = ++id;
  return new Promise((resolve) => {
    pending.set(msgId, resolve);
    proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: msgId, method, params }) + '\n');
  });
}

await request('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 't', version: '0' } });
proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');

const hash = '0x' + 'cd'.repeat(32);
let failures = 0;
function check(name, cond) {
  if (cond) console.log(`PASS  ${name}`);
  else { failures++; console.log(`FAIL  ${name}`); }
}

const small = await request('tools/call', { name: 'sign', arguments: { hash, amount: '5' } });
check('small amount signs', /^0x[0-9a-f]+/.test(small?.result?.content?.[0]?.text || ''));

const medium = await request('tools/call', { name: 'sign', arguments: { hash, amount: '50' } });
const mtext = medium?.result?.content?.[0]?.text || '';
check('medium amount is TIMEDLOCKED (P0 fix)', medium?.result?.isError === true && /Timelocked/i.test(mtext));

const large = await request('tools/call', { name: 'sign', arguments: { hash, amount: '500' } });
check('large amount denied', large?.result?.isError === true && /requires human approval/i.test(large?.result?.content?.[0]?.text || ''));

const none = await request('tools/call', { name: 'sign', arguments: { hash } });
check('no amount (message signing) signs', /^0x[0-9a-f]+/.test(none?.result?.content?.[0]?.text || ''));

proc.kill();
console.log(failures === 0 ? '\nALL MCP SIGN-TIER CHECKS PASSED' : `\n${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);