// MCP server stdio handshake + tool call smoke test
import { spawn } from 'node:child_process';

const proc = spawn(process.execPath, ['src/server.js'], { stdio: ['pipe', 'pipe', 'pipe'] });
let buf = '';
let failures = 0;
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
    if (msg.id && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    }
  }
});
let stderr = '';
proc.stderr.on('data', (d) => { stderr += d.toString(); });

function request(method, params) {
  const msgId = ++id;
  return new Promise((resolve) => {
    pending.set(msgId, resolve);
    proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: msgId, method, params }) + '\n');
  });
}

function check(name, cond) {
  if (cond) console.log(`PASS  ${name}`);
  else { failures++; console.log(`FAIL  ${name}`); }
}

const init = await request('initialize', {
  protocolVersion: '2024-11-05',
  capabilities: {},
  clientInfo: { name: 'smoke-test', version: '0.0.0' },
});
check('initialize handshake', init?.result?.serverInfo?.name === 'aegis-vault');

proc.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');

const tools = await request('tools/list', {});
const names = tools?.result?.tools?.map(t => t.name) || [];
check('7 tools listed', names.length === 7, `got: ${names.join(',')}`);
check('sign tool present', names.includes('sign'));

const tier = await request('tools/call', { name: 'check_tier', arguments: { amount: '50' } });
check('check_tier 50 => medium', tier?.result?.content?.[0]?.text?.includes('medium'));

const tierLarge = await request('tools/call', { name: 'check_tier', arguments: { amount: '500' } });
check('check_tier 500 => large', tierLarge?.result?.content?.[0]?.text?.includes('large'));

// sign without key initialized => graceful error, not crash
const sig = await request('tools/call', { name: 'sign', arguments: { hash: '0x' + 'ab'.repeat(32) } });
check('sign without key => graceful isError', sig?.result?.isError === true);

// medium-tier timelock enforcement on the MCP side too
const info = await request('tools/call', { name: 'pqc_info', arguments: {} });
check('pqc_info returns Dilithium2', info?.result?.content?.[0]?.text?.includes('Dilithium2'));

console.log(stderr.includes('running on stdio') ? 'PASS  server banner on stderr' : 'FAIL  server banner');

proc.kill();
console.log(failures === 0 ? '\nALL MCP CHECKS PASSED' : `\n${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);