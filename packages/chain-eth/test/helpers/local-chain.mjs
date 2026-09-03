/**
 * LocalChain — an in-process Ethereum dev chain used by the Sprint 2.3 on-chain
 * E2E tests.
 *
 * WHY IT EXISTS
 * ─────────────
 * anvil / ganache are not reliably installable in this environment, so we build
 * a minimal but REAL EVM chain on top of @ethereumjs/vm and expose it through a
 * JSON-RPC-compatible HTTP endpoint. ethers.js `JsonRpcProvider` connects to it
 * exactly like a remote chain — the Smart Account broadcast flow
 * (registerSession / executeFromAgent over the wire) is exercised against
 * genuine EVM state, not a JS simulation.
 *
 * SUPPORTED METHODS (ethers v6 read/write path):
 *   eth_chainId / eth_blockNumber / eth_gasPrice / eth_maxPriorityFeePerGas
 *   eth_getBalance / eth_getTransactionCount / eth_getCode
 *   eth_sendRawTransaction / eth_call / eth_estimateGas
 *   eth_getTransactionReceipt / eth_getTransactionByHash / eth_getBlockByNumber
 *   eth_feeHistory (minimal) / eth_getLogs (filter by address+topics)
 *
 * TIME CONTROL
 * ────────────
 * SmartAccount.sol reads `block.timestamp` for session expiry (INV-003) and the
 * rolling spend window (INV-007). LocalChain carries an internal clock
 * (`setTime(msEpoch)` / `advanceTime(ms)`) so tests can move past an expiry
 * without sleeping.
 */
import http from 'node:http';
import { Mainnet, createCustomCommon } from '@ethereumjs/common';
import { createVM, runTx } from '@ethereumjs/vm';
import { createTxFromRLP } from '@ethereumjs/tx';
import { createBlock } from '@ethereumjs/block';
import {
  createAccount,
  createAddressFromString,
  bytesToHex,
  hexToBytes,
  bigIntToBytes,
  setLengthLeft,
} from '@ethereumjs/util';
import { SimpleStateManager } from '@ethereumjs/statemanager';

const HARDHAT_CHAIN_ID = 31337;
const DEFAULT_GAS_LIMIT = 30_000_000n;

/**
 * Create and start a LocalChain.
 *
 * @param {object} [opts]
 * @param {number} [opts.chainId=31337]
 * @param {string} [opts.hardfork='paris']
 * @param {number} [opts.port=0] 0 → OS-assigned ephemeral port
 * @param {number} [opts.initialTimeMs] chain clock start (default Date.now())
 * @param {Array<{address:string,balance:bigint}>} [opts.funded] pre-funded accounts
 * @returns {Promise<LocalChain>}
 */
export async function createLocalChain({
  chainId = HARDHAT_CHAIN_ID,
  hardfork = 'paris',
  port = 0,
  initialTimeMs = Date.now(),
  funded = [],
} = {}) {
  const common = createCustomCommon(
    { name: `local-${chainId}`, chainId, defaultHardfork: hardfork },
    Mainnet
  );
  const stateManager = new SimpleStateManager({ common });
  const vm = await createVM({ common, stateManager });

  // ── Internal state ──────────────────────────────────────────────────────
  let clockMs = initialTimeMs;
  const chain = new LocalChain({ vm, common, stateManager, chainId });

  // Pre-fund
  for (const { address, balance } of funded) {
    await chain.credit(address, balance);
  }

  // ── JSON-RPC server ─────────────────────────────────────────────────────
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const send = (code, payload) => {
        res.writeHead(code, { 'content-type': 'application/json' });
        res.end(JSON.stringify(payload));
      };
      let rpc;
      try {
        rpc = JSON.parse(body || '{}');
      } catch {
        return send(400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } });
      }
      // Batch JSON-RPC (ethers v6 sends batched eth_chainId + eth_blockNumber).
      if (Array.isArray(rpc)) {
        Promise.all(rpc.map((r) => chain.handle(r).then((result) => ({ jsonrpc: '2.0', id: r.id ?? null, result })).catch((err) => ({ jsonrpc: '2.0', id: r.id ?? null, error: { code: -32000, message: err.message, ...(err?.revertData ? { data: err.revertData } : {}) } }))))
          .then((results) => send(200, results));
        return;
      }
      if (process.env.LOCAL_CHAIN_DEBUG) console.log('[rpc]', rpc.method, JSON.stringify(rpc.params ?? []).slice(0, 120));
      if (rpc.method === undefined) return send(400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'invalid request' } });
      chain
        .handle(rpc)
        .then((result) => send(200, { jsonrpc: '2.0', id: rpc.id ?? null, result }))
        .catch((err) => {
          send(200, {
            jsonrpc: '2.0',
            id: rpc.id ?? null,
            error: {
              code: -32000,
              message: err.message,
              // `data` must carry the raw revert payload (hex) — ethers v6
              // decodes custom errors / revert strings from this field.
              ...(err?.revertData ? { data: err.revertData } : {}),
            },
          });
        });
    });
  });

  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
  const actualPort = server.address().port;
  chain._server = server;
  chain._url = `http://127.0.0.1:${actualPort}`;

  chain._clock = () => BigInt(Math.floor(clockMs / 1000));
  chain.setTime = (ms) => {
    clockMs = ms;
  };
  chain.advanceTime = (ms) => {
    clockMs += ms;
  };

  return chain;
}

class LocalChain {
  constructor({ vm, common, stateManager, chainId }) {
    this.vm = vm;
    this.common = common;
    this.sm = stateManager;
    this.chainId = chainId;
    /** hash → { tx, runResult, blockNumber, transactionIndex } */
    this.txs = new Map();
    this.logs = [];
    this._server = null;
    this._url = null;
    this._clock = () => BigInt(Math.floor(Date.now() / 1000));
    this._blockNumber = 1n;
  }

  get url() {
    return this._url;
  }

  async stop() {
    if (this._server) await new Promise((r) => this._server.close(r));
  }

  // ── Account helpers ─────────────────────────────────────────────────────
  async credit(address, balance) {
    const addr = createAddressFromString(address);
    const acc = (await this.sm.getAccount(addr)) ?? createAccount({});
    await this.sm.putAccount(addr, createAccount({ nonce: acc.nonce, balance: acc.balance + balance }));
  }

  async getAccountData(address) {
    const acc = (await this.sm.getAccount(createAddressFromString(address))) ?? createAccount({});
    return {
      balance: acc.balance,
      nonce: acc.nonce,
      code: bytesToHex(await this.sm.getCode(createAddressFromString(address))),
    };
  }

  // ── Core execution ──────────────────────────────────────────────────────
  async _nextBlock() {
    this._blockNumber += 1n;
    return createBlock(
      {
        header: {
          timestamp: this._clock(),
          number: this._blockNumber,
          gasLimit: DEFAULT_GAS_LIMIT,
          baseFeePerGas: 0n,
        },
      },
      { common: this.common }
    );
  }

  async _runRaw(raw) {
    const tx = createTxFromRLP(hexToBytes(raw), { common: this.common });
    const block = await this._nextBlock();
    const res = await runTx(this.vm, { tx, block, skipBalance: false, skipNonce: false });
    return { tx, block, res };
  }

  async _call({ from, to, data }) {
    // eth_call: execute in a checkpointed frame, then revert (no state change).
    await this.sm.checkpoint();
    try {
      const block = createBlock(
        { header: { timestamp: this._clock(), number: this._blockNumber, gasLimit: DEFAULT_GAS_LIMIT, baseFeePerGas: 0n } },
        { common: this.common }
      );
      const res = await this.vm.evm.runCall({
        block,
        caller: from ? createAddressFromString(from) : createAddressFromString('0x0000000000000000000000000000000000000000'),
        to: to ? createAddressFromString(to) : undefined,
        data: data ? hexToBytes(data) : new Uint8Array(0),
        gasLimit: DEFAULT_GAS_LIMIT,
        skipBalance: true,
      });
      if (res.execResult?.exceptionError) {
        // Attach the revert payload (custom-error selector + args, or the
        // `revert(reason)` string) so the JSON-RPC layer can forward it to
        // ethers, which decodes it into a typed error (e.g. BadNonce /
        // AmountExceedsPerTx / SessionExpired).
        const err = new Error(`execution reverted: ${res.execResult.exceptionError.error}`);
        const revertData = res.execResult.returnValue ?? new Uint8Array(0);
        if (revertData.length > 0) err.revertData = bytesToHex(revertData);
        throw err;
      }
      return res.execResult.returnValue ?? new Uint8Array(0);
    } finally {
      await this.sm.revert();
    }
  }

  // ── JSON-RPC dispatch ───────────────────────────────────────────────────
  async handle(rpc) {
    const { method, params = [] } = rpc;
    switch (method) {
      case 'eth_chainId':
        return '0x' + this.chainId.toString(16);
      case 'eth_blockNumber':
        return '0x' + this._blockNumber.toString(16);
      case 'eth_gasPrice':
        return '0x1';
      case 'eth_maxPriorityFeePerGas':
        return '0x1';
      case 'eth_feeHistory':
        return { oldestBlock: '0x0', baseFeePerGas: [], gasUsedRatio: [] };
      case 'eth_getBalance': {
        const acc = await this.getAccountData(params[0]);
        return '0x' + acc.balance.toString(16);
      }
      case 'eth_getTransactionCount': {
        const acc = await this.getAccountData(params[0]);
        const result = '0x' + acc.nonce.toString(16);
        if (process.env.LOCAL_CHAIN_DEBUG) console.log(`[txcount:${this._url}]`, params[0]?.slice(0, 10), params[1], '→', result);
        return result;
      }
      case 'eth_getCode':
        return (await this.getAccountData(params[0])).code;
      case 'eth_getStorageAt': {
        const { getContractStorage } = await import('@ethereumjs/statemanager');
        const val = await this.sm.getStorage(createAddressFromString(params[0]), hexToBytes(params[1]));
        return bytesToHex(setLengthLeft(val, 32));
      }
      case 'eth_estimateGas': {
        // Behave like a real node: SIMULATE the call so reverts surface at
        // pre-flight (ethers runs estimateGas before broadcasting when no
        // gasLimit is given). The revert payload is attached to the error and
        // forwarded as JSON-RPC error.data, exactly like geth/erigon — this is
        // what lets ethers decode typed errors BEFORE the tx is ever sent.
        const req = params[0] ?? {};
        await this._call({ from: req.from, to: req.to, data: req.data });
        return '0x' + DEFAULT_GAS_LIMIT.toString(16);
      }
      case 'eth_sendRawTransaction': {
        const { tx, res } = await this._runRaw(params[0]);
        const hash = bytesToHex(tx.hash());
        this.txs.set(hash.toLowerCase(), { tx, res, blockNumber: this._blockNumber, transactionIndex: this.txs.size });
        // RunTxResult exposes logs at `execResult.logs` (NOT `res.logs`, which
        // silently yielded [] and broke every event assertion). Each log is a
        // TUPLE [address, topics[], data] in @ethereumjs/vm@10 — not an object.
        for (const log of res.execResult?.logs ?? []) {
          this.logs.push({
            address: bytesToHex(log[0]),
            topics: (log[1] ?? []).map((t) => bytesToHex(t)),
            data: bytesToHex(log[2] ?? new Uint8Array(0)),
          });
        }
        return hash;
      }
      case 'eth_call': {
        const req = params[0] ?? {};
        const returnValue = await this._call({ from: req.from, to: req.to, data: req.data });
        return bytesToHex(returnValue);
      }
      case 'eth_getTransactionReceipt': {
        const entry = this.txs.get(String(params[0]).toLowerCase());
        if (!entry) return null;
        const { tx, res, blockNumber, transactionIndex } = entry;
        const status = res.execResult.exceptionError ? 0 : 1;
        const contractAddress = tx.to ? null : res.createdAddress?.toString() ?? null;
        return {
          transactionHash: bytesToHex(tx.hash()),
          transactionIndex: '0x' + transactionIndex.toString(16),
          blockNumber: '0x' + blockNumber.toString(16),
          blockHash: '0x' + '00'.repeat(32),
          from: tx.getSenderAddress().toString(),
          to: tx.to ? tx.to.toString() : null,
          cumulativeGasUsed: '0x0',
          gasUsed: '0x' + res.totalGasSpent.toString(16),
          contractAddress,
          logs: (res.execResult?.logs ?? []).map((l) => ({
            address: bytesToHex(l[0]),
            topics: (l[1] ?? []).map((t) => bytesToHex(t)),
            data: bytesToHex(l[2] ?? new Uint8Array(0)),
            blockNumber: '0x' + blockNumber.toString(16),
            transactionHash: bytesToHex(tx.hash()),
            transactionIndex: '0x' + transactionIndex.toString(16),
            blockHash: '0x' + '00'.repeat(32),
            logIndex: '0x0',
            removed: false,
          })),
          logsBloom: '0x' + '00'.repeat(256),
          status: '0x' + status.toString(16),
          effectiveGasPrice: '0x1',
        };
      }
      case 'eth_getTransactionByHash': {
        const entry = this.txs.get(String(params[0]).toLowerCase());
        if (!entry) return null;
        const { tx, blockNumber, transactionIndex } = entry;
        return {
          hash: bytesToHex(tx.hash()),
          nonce: '0x' + tx.nonce.toString(16),
          blockHash: '0x' + '00'.repeat(32),
          blockNumber: '0x' + blockNumber.toString(16),
          transactionIndex: '0x' + transactionIndex.toString(16),
          from: tx.getSenderAddress().toString(),
          to: tx.to ? tx.to.toString() : null,
          value: '0x' + tx.value.toString(16),
          gasPrice: '0x1',
          gas: '0x' + tx.gasLimit.toString(16),
          input: bytesToHex(tx.data),
        };
      }
      case 'eth_getBlockByNumber': {
        const number = params[0];
        const blockNumberHex = '0x' + this._blockNumber.toString(16);
        return {
          number: blockNumberHex,
          hash: '0x' + '00'.repeat(32),
          parentHash: '0x' + '00'.repeat(32),
          nonce: '0x0000000000000000',
          timestamp: '0x' + this._clock().toString(16),
          difficulty: '0x0',
          totalDifficulty: '0x0',
          gasLimit: '0x' + DEFAULT_GAS_LIMIT.toString(16),
          gasUsed: '0x0',
          miner: '0x0000000000000000000000000000000000000000',
          extraData: '0x',
          baseFeePerGas: '0x0',
          transactions: [],
        };
      }
      case 'eth_getLogs': {
        const filter = params[0] ?? {};
        const addressFilter = filter.address ? filter.address.toLowerCase() : null;
        const topics = (filter.topics ?? []).filter(Boolean).map((t) => t.toLowerCase());
        return this.logs
          .filter((l) => (!addressFilter || l.address.toLowerCase() === addressFilter) && topics.every((t, i) => !t || (l.topics[i] ?? '').toLowerCase() === t))
          .map((l) => ({ ...l, blockNumber: '0x' + this._blockNumber.toString(16), transactionHash: '0x', transactionIndex: '0x0', blockHash: '0x' + '00'.repeat(32), logIndex: '0x0', removed: false }));
      }
      case 'eth_accounts':
        return [];
      default:
        throw new Error(`unsupported method: ${method}`);
    }
  }
}
