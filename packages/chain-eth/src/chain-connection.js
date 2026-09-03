/**
 * aegis-chain-eth — Smart Account ON-CHAIN broadcast layer (Sprint 2.3)
 *
 * PURPOSE
 * ───────
 * The JS `SmartAccount` engine (smart-account.js) is a faithful, stateful
 * mirror of the Solidity `SmartAccount` contract. This module closes the loop:
 * it drives the REAL contract on a live chain through ethers.js, so an agent /
 * SDK / MCP can:
 *
 *   - deploy a fresh SmartAccount (deploySmartAccount), or
 *   - attach to an existing one (createChainConnection), and
 *   - broadcast registerSession / executeFromAgent / revoke / pause / freeze
 *     transactions, with on-chain state queries and typed revert decoding.
 *
 * The execution path is IDENTICAL to the JS engine's fail-closed semantics:
 * every check (session validity, whitelist, self-escalation deny-list,
 * allowance surface, per-tx + cumulative ceilings, nonce anti-replay) runs in
 * the contract against the canonical 12-field digest. The JS side here only
 * maps the canonical payload → the contract's `IntentFields` struct and
 * submits the already-signed (r,s,v) signature.
 *
 * SECURITY
 * ────────
 * - The agent signs OFF-CHAIN with `signSmartAccountIntent` (see canonical.js);
 *   this module never holds an agent private key.
 * - `registerSession` / `revokeSession` / `pause` / `freeze` / `resume` /
 *   `unfreeze` / `emergencyReduceLimit` are privileged and MUST be sent from
 *   the owner / emergency signer — enforced by the contract's modifiers
 *   (onlyOwner / onlyEmergency), never trusted here.
 * - `executeFromAgent` can be broadcast by ANY EOA: the contract authenticates
 *   the signature against the session's registered EVM address (INV-002).
 */
import { Contract, ContractFactory, Interface, JsonRpcProvider } from 'ethers';
import { hashIntentDigest } from './canonical.js';

// ─── Struct mapping ───────────────────────────────────────────────────────

/**
 * Map a canonical intent payload → the contract's `IntentFields` struct.
 *
 * The only rename is `payload.contract` → `struct.contractAddr` (the Solidity
 * struct field is `contractAddr` because `contract` is a reserved word).
 * Numeric fields are converted to BigInt; sessionId must be 32-byte hex.
 *
 * @param {object} payload - canonicalizeAssetIntent() / signSmartAccountIntent() payload
 * @returns {object} struct literal accepted by ethers tuple encoding
 */
export function intentToStruct(payload) {
  if (!payload || typeof payload !== 'object') {
    throw new Error('intentToStruct requires a canonical intent payload');
  }
  const sessionId = String(payload.sessionId ?? '').replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{64}$/.test(sessionId)) {
    throw new Error(`sessionId must be 32-byte hex, got: ${payload.sessionId}`);
  }
  return {
    sessionId: payload.sessionId,
    action: String(payload.action ?? ''),
    chain: String(payload.chain ?? ''),
    asset: String(payload.asset ?? ''),
    amount: BigInt(payload.amount),
    recipient: String(payload.recipient ?? ''),
    contractAddr: String(payload.contract ?? ''),
    method: String(payload.method ?? ''),
    nonce: BigInt(payload.nonce),
    agentId: String(payload.agentId ?? ''),
    sessionIssuedAt: BigInt(payload.sessionIssuedAt),
    sessionExpiresAt: BigInt(payload.sessionExpiresAt),
  };
}

/**
 * Compute the canonical digest for a payload without signing — convenience
 * mirror of SmartAccount.hashIntent (the on-chain view) for cross-checking.
 * @param {object} payload - canonical intent payload
 * @returns {string} '0x' + 64 hex
 */
export function payloadDigest(payload) {
  return hashIntentDigest(payload);
}

// ─── Revert / error decoding ─────────────────────────────────────────────

/**
 * Normalize a contract call/estimate error into a structured, typed result.
 *
 * ethers v6 surfaces custom errors in ONE of two shapes depending on the RPC
 * path used (single `eth_call` vs. a batched request):
 *
 *   - `err.info.error` — ErrorDescription with `.name` + `.args`, with the raw
 *     payload on `err.revert` (hex string).
 *   - `err.revert` — the ErrorDescription object directly (batch path), with
 *     the raw payload on `err.data`.
 *
 * We reduce all of it to a stable shape so callers can assert on `errorName`
 * instead of string-matching messages.
 *
 * @param {unknown} err - thrown error from a Contract call/estimate/tx
 * @returns {{ ok: false, errorName: string|null, args: unknown[]|null,
 *             revertData: string|null, reason: string }}
 */
export function decodeRevert(err) {
  const info = err?.info ?? err;
  const revert = err?.revert ?? null;
  // ErrorDescription can live on `info.error` (single-call path) or be the
  // whole `err.revert` (batch path).
  const decoded = info?.error ?? (revert && typeof revert === 'object' ? revert : null);
  return {
    ok: false,
    errorName: decoded?.name ?? null,
    args: decoded?.args ?? null,
    revertData: typeof revert === 'string' ? revert : (err?.data ?? null),
    reason: err?.reason ?? err?.message ?? String(err),
  };
}

/**
 * decodeRevert + ABI-aware fallback for BROADCAST-path errors.
 *
 * The pre-flight `eth_estimateGas` revert (what a real node returns when a
 * tx WOULD revert) reaches ethers as a CallException carrying only the RAW
 * revert payload on `err.data` — ethers does NOT decode it into an
 * ErrorDescription on the send path (unlike staticCall). A receipt-level
 * failure (`tx.wait()` on status 0) carries no payload at all.
 *
 * So when decodeRevert yields no errorName, we parse the raw revert data
 * against the contract ABI ourselves.
 *
 * @param {unknown} err - thrown error from a Contract call/estimate/tx
 * @param {ethers.Interface} iface - contract ABI interface
 * @returns {object} decodeRevert shape, with errorName/args decoded when possible
 */
function decodeFailure(err, iface) {
  const base = decodeRevert(err);
  if (base.errorName != null) return base;
  const data = base.revertData;
  if (!iface || typeof data !== 'string' || data === '0x' || data.length < 10) {
    return base;
  }
  try {
    const parsed = iface.parseError(data);
    if (parsed?.name) {
      return { ...base, errorName: parsed.name, args: parsed.args };
    }
  } catch {
    // Unknown error selector — keep the raw shape.
  }
  return base;
}

/** Clamp an env integer to [min, max]; `fallback` when unset/invalid. */
function clampInt(raw, fallback, min, max) {
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

/** Resolve the provider backing a Contract (runner may be a Signer or a Provider). */
function providerFor(contract) {
  const runner = contract.runner;
  if (runner && typeof runner.getTransactionReceipt === 'function') return runner;
  return runner?.provider ?? null;
}

// ─── Chain connection ─────────────────────────────────────────────────────

/**
 * Smart Account chain connection.
 *
 * Wraps an ethers Contract + optional signer for one deployed SmartAccount.
 * All privileged ops require `signer`; pass an owner/emergency wallet at
 * construction or per-call via `{ signer }`.
 */
export class ChainConnection {
  /**
   * @param {object} opts
   * @param {ethers.Contract} opts.contract - ethers Contract (abi + address + signer)
   * @param {string} opts.address - contract address
   */
  constructor({ contract, address }) {
    this.contract = contract;
    this.address = address;
  }

  // ── Read views ─────────────────────────────────────────────────────────

  async owner() {
    return this.contract.owner();
  }
  async emergencyKey() {
    return this.contract.emergencyKey();
  }
  async paused() {
    return this.contract.paused();
  }
  async frozen() {
    return this.contract.frozen();
  }
  async accountMaxDaily() {
    return this.contract.accountMaxDaily();
  }
  async accountSpentThisWindow() {
    return this.contract.accountSpentThisWindow();
  }
  async sessionLastNonce(sessionId) {
    return this.contract.sessionLastNonce(sessionId);
  }
  async sessionSpentThisWindow(sessionId) {
    return this.contract.sessionSpentThisWindow(sessionId);
  }
  async estimateMaxLoss() {
    return this.contract.estimateMaxLoss();
  }
  async sessionMaxLoss(sessionId) {
    return this.contract.sessionMaxLoss(sessionId);
  }

  /** On-chain canonical digest for a payload (cross-check with JS side). */
  async hashIntent(payload) {
    return this.contract.hashIntent(intentToStruct(payload));
  }

  // ── Privileged: session lifecycle (owner signer) ───────────────────────

  /**
   * Register a session on-chain (owner only).
   * @param {object} opts
   * @param {string} opts.sessionId - 32-byte hex
   * @param {string} opts.agentId
   * @param {string} opts.agentEvmAddress
   * @param {number|bigint|string} opts.issuedAt - ms epoch
   * @param {number|bigint|string} opts.expiresAt - ms epoch
   * @param {string|number|bigint} [opts.maxPerTx=0]
   * @param {string|number|bigint} [opts.maxDaily=0]
   * @param {object} [opts.whitelist] - { allowedChains?, allowedAssets?,
   *   allowedContracts?, allowedMethods?, allowedRecipients? }
   * @param {ethers.Signer} [opts.signer] - defaults to the connection signer
   * @returns {Promise<{ok: true, txHash, receipt, sessionId} | {ok:false,...}>}
   */
  async registerSession({
    sessionId, agentId, agentEvmAddress, issuedAt, expiresAt,
    maxPerTx = 0, maxDaily = 0, whitelist = {}, signer,
  } = {}) {
    const hex = String(sessionId ?? '').replace(/^0x/i, '');
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
      return { ok: false, reason: `sessionId must be 32-byte hex, got: ${sessionId}` };
    }
    const w = whitelist || {};
    const arr = (k) => (w[k] === undefined || w[k] === null ? [] : Array.isArray(w[k]) ? w[k] : [w[k]]);
    const runner = signer ?? this.contract.runner;
    try {
      const tx = await this.contract
        .connect(runner)
        .registerSession(
          sessionId,
          String(agentId),
          agentEvmAddress,
          BigInt(issuedAt),
          BigInt(expiresAt),
          BigInt(maxPerTx),
          BigInt(maxDaily),
          arr('allowedChains'),
          arr('allowedAssets'),
          arr('allowedContracts'),
          arr('allowedMethods'),
          arr('allowedRecipients'),
        );
      const receipt = await tx.wait();
      return { ok: true, txHash: tx.hash, receipt, sessionId };
    } catch (err) {
      return { ok: false, ...decodeFailure(err, this.contract.interface), sessionId };
    }
  }

  /**
   * Revoke a session (owner).
   * @returns {Promise<{ok: true, txHash, receipt, sessionId} | {ok:false,...}>}
   */
  async revokeSession({ sessionId, signer } = {}) {
    try {
      const tx = await this.contract.connect(signer ?? this.contract.runner).revokeSession(sessionId);
      const receipt = await tx.wait();
      return { ok: true, txHash: tx.hash, receipt, sessionId };
    } catch (err) {
      return { ok: false, ...decodeFailure(err, this.contract.interface), sessionId };
    }
  }

  /**
   * Emergency brake: pause (emergency signer).
   * @returns {Promise<{ok: true, txHash, receipt} | {ok:false,...}>}
   */
  async pause({ signer } = {}) {
    try {
      const tx = await this.contract.connect(signer ?? this.contract.runner).pause();
      const receipt = await tx.wait();
      return { ok: true, txHash: tx.hash, receipt };
    } catch (err) {
      return { ok: false, ...decodeFailure(err, this.contract.interface) };
    }
  }

  /**
   * Owner only: resume.
   * @returns {Promise<{ok: true, txHash, receipt} | {ok:false,...}>}
   */
  async resume({ signer } = {}) {
    try {
      const tx = await this.contract.connect(signer ?? this.contract.runner).resume();
      const receipt = await tx.wait();
      return { ok: true, txHash: tx.hash, receipt };
    } catch (err) {
      return { ok: false, ...decodeFailure(err, this.contract.interface) };
    }
  }

  /**
   * Emergency brake: freeze (emergency signer).
   * @returns {Promise<{ok: true, txHash, receipt} | {ok:false,...}>}
   */
  async freeze({ signer } = {}) {
    try {
      const tx = await this.contract.connect(signer ?? this.contract.runner).freeze();
      const receipt = await tx.wait();
      return { ok: true, txHash: tx.hash, receipt };
    } catch (err) {
      return { ok: false, ...decodeFailure(err, this.contract.interface) };
    }
  }

  /**
   * Owner only: unfreeze.
   * @returns {Promise<{ok: true, txHash, receipt} | {ok:false,...}>}
   */
  async unfreeze({ signer } = {}) {
    try {
      const tx = await this.contract.connect(signer ?? this.contract.runner).unfreeze();
      const receipt = await tx.wait();
      return { ok: true, txHash: tx.hash, receipt };
    } catch (err) {
      return { ok: false, ...decodeFailure(err, this.contract.interface) };
    }
  }

  /**
   * Emergency reduce-only (emergency signer). Attempts to RAISE a ceiling are
   * rejected on-chain (INV-006) — surfaced here as a typed revert.
   * @returns {Promise<{ok: true, txHash, receipt, sessionId} | {ok:false,...}>}
   */
  async emergencyReduceLimit({ sessionId, maxPerTx, maxDaily, signer } = {}) {
    try {
      const tx = await this.contract
        .connect(signer ?? this.contract.runner)
        .emergencyReduceLimit(sessionId, BigInt(maxPerTx ?? 0), BigInt(maxDaily ?? 0));
      const receipt = await tx.wait();
      return { ok: true, txHash: tx.hash, receipt, sessionId };
    } catch (err) {
      return { ok: false, ...decodeFailure(err, this.contract.interface), sessionId };
    }
  }

  /**
   * Side-effect-free simulation of an agent execution via `eth_call`
   * (staticCall). The contract runs the FULL fail-closed decision tree; on
   * rejection the revert is decoded into a typed error (errorName/args),
   * exactly like the JS `preview` mode in smart-account.js — but against the
   * REAL on-chain state.
   *
   * @param {object} opts - same as executeFromAgent (signer ignored for eth_call)
   * @returns {Promise<{ok:true, txId} | {ok:false,...}>}
   */
  async simulateExecuteFromAgent({ payload, signature, signer } = {}) {
    let struct;
    try {
      struct = intentToStruct(payload);
    } catch (err) {
      return { ok: false, reason: err.message };
    }
    try {
      const signerForCall = signer ?? this.contract.runner;
      const txId = await this.contract
        .connect(signerForCall)
        .executeFromAgent.staticCall(struct, signature);
      return { ok: true, txId };
    } catch (err) {
      return { ok: false, ...decodeRevert(err) };
    }
  }

  // ── Core: broadcast an agent execution ──────────────────────────────────

  /**
   * Broadcast an agent-signed intent to the chain. The contract re-derives
   * every property from the signed digest (INV-002/003/005/006/007) and
   * authenticates the signature against the session's registered EVM address.
   *
   * The signature MUST come from `signSmartAccountIntent` / `signIntentDigest`
   * (plain raw digest, low-S, 65-byte r||s||v).
   *
   * @param {object} opts
   * @param {object} opts.payload - canonical intent payload
   * @param {string} opts.signature - 65-byte (r||s||v) hex signature
   * @param {ethers.Signer} [opts.signer] - broadcaster EOA (anyone may relay)
   * @param {string|number|bigint} [opts.nonce] - Sprint 6 T4: explicit EOA nonce
   *   override, passed as the ethers tx override. When omitted (default/legacy)
   *   ethers reads a fresh nonce from the node, exactly as before. Only used by
   *   the distributed nonce coordinator (relayer-coordinator.js).
   * @returns {Promise<{ok: true, txHash, receipt, txId, amount, sessionId} | {ok:false,...}>}
   */
  async executeFromAgent({ payload, signature, signer, nonce } = {}) {
    let struct;
    try {
      struct = intentToStruct(payload);
    } catch (err) {
      return { ok: false, reason: err.message };
    }
    try {
      // Sprint 6 T4: an explicit EOA nonce override is appended ONLY when one was
      // coordinated. Passing a trailing `undefined` here would make ethers treat
      // it as a 3rd positional arg and fail to match the 2-arg executeFromAgent
      // fragment ("no matching fragment") — so when nonce is absent we keep the
      // exact legacy 2-arg call.
      const connected = this.contract.connect(signer ?? this.contract.runner);
      const tx = nonce != null
        ? await connected.executeFromAgent(struct, signature, { nonce: BigInt(nonce) })
        : await connected.executeFromAgent(struct, signature);
      let receipt;
      try {
        receipt = await tx.wait();
      } catch (waitErr) {
        // RPC flake AFTER broadcast (T3.2): the tx may still mine. Reconcile by
        // polling the receipt instead of losing the tx — otherwise a later
        // retry would re-broadcast (idempotent at the contract's intent-nonce
        // level, but wasteful and confusing for the operator).
        const reason = waitErr?.reason ?? waitErr?.message ?? String(waitErr);
        const recProvider = providerFor(this.contract);
        const attempts = clampInt(process.env.RELAYER_RECONCILE_ATTEMPTS, 3, 0, 20);
        for (let i = 0; recProvider && i <= attempts; i++) {
          if (i > 0) await new Promise((r) => setTimeout(r, 200));
          try {
            const found = await recProvider.getTransactionReceipt(tx.hash);
            if (found) { receipt = found; break; }
          } catch {
            /* keep polling */
          }
        }
        if (!receipt) return { ok: false, txHash: tx.hash, waitFailed: true, reason };
      }
      // A mined-but-reverted tx is a FAILURE, not a success with status=0 —
      // surface it as such so the ledger/audit don't report a contradiction.
      if (receipt.status === 0) {
        return { ok: false, txHash: tx.hash, receipt, errorName: null, reason: 'transaction reverted on-chain' };
      }
      // The contract emits Executed(sessionId, txId, amount) — decode it for
      // a structured result instead of re-hashing off-chain.
      const executed = (receipt.logs ?? [])
        .map((l) => {
          try {
            return this.contract.interface.parseLog({ topics: l.topics, data: l.data });
          } catch {
            return null;
          }
        })
        .find((p) => p?.name === 'Executed');
      return {
        ok: true,
        txHash: tx.hash,
        receipt,
        txId: executed ? executed.args.txId : null,
        amount: executed ? executed.args.amount : null,
        sessionId: executed ? executed.args.sessionId : null,
      };
    } catch (err) {
      return { ok: false, ...decodeFailure(err, this.contract.interface) };
    }
  }
}

// ─── Factories ────────────────────────────────────────────────────────────

/**
 * Create a JSON-RPC provider for Smart Account broadcast traffic.
 *
 * ethers v6's AbstractProvider de-duplicates identical requests for 250ms
 * (its `cacheTimeout`). For a broadcast path that is WRONG: after the first
 * tx from an EOA is mined, a follow-up `eth_getTransactionCount(addr,
 * "pending")` issued within that window returns the STALE cached nonce,
 * which the node then rejects ("tx doesn't have the correct nonce").
 *
 * We therefore disable the cache (cacheTimeout: -1) so every populated tx
 * reads a fresh nonce, exactly like a wallet UI would.
 *
 * @param {string} url - JSON-RPC endpoint
 * @returns {ethers.JsonRpcProvider}
 */
export function createChainProvider(url) {
  return new JsonRpcProvider(url, undefined, { cacheTimeout: -1 });
}

/**
 * Deploy a fresh SmartAccount contract.
 *
 * @param {object} opts
 * @param {string|ethers.Provider} opts.provider - URL or ethers Provider
 * @param {ethers.Signer} opts.signer - EOA that pays the deployment
 * @param {object} opts.abi - contract ABI
 * @param {string} opts.bytecode - contract creation bytecode ('0x' + hex)
 * @param {string} opts.owner - owner address
 * @param {string} opts.emergencyKey - emergency address
 * @param {string|number|bigint} [opts.accountMaxDaily=1000000]
 * @returns {Promise<{ok: true, address, connection: ChainConnection, receipt, txHash} | {ok:false,...}>}
 */
export async function deploySmartAccount({
  provider, signer, abi, bytecode, owner, emergencyKey, accountMaxDaily = 1_000_000,
} = {}) {
  const signerWithProvider = provider
    ? signer.connect(typeof provider === 'string' ? createChainProvider(provider) : provider)
    : signer;
  const factory = new ContractFactory(abi, bytecode, signerWithProvider);
  try {
    const contract = await factory.deploy(owner, emergencyKey, BigInt(accountMaxDaily));
    const receipt = await contract.deploymentTransaction().wait();
    const address = await contract.getAddress();
    return {
      ok: true,
      address,
      connection: new ChainConnection({ contract, address }),
      receipt,
      txHash: contract.deploymentTransaction().hash,
    };
  } catch (err) {
    // Constructor reverts (NotOwner/NotEmergency/NoAccountCeiling) surface at
    // pre-flight estimateGas with raw data only — decode against the ABI.
    return { ok: false, ...decodeFailure(err, new Interface(abi)) };
  }
}

/**
 * Attach to an already-deployed SmartAccount.
 *
 * @param {object} opts
 * @param {string|ethers.Provider} opts.provider - URL or ethers Provider
 * @param {string} opts.address - deployed contract address
 * @param {object} opts.abi - contract ABI
 * @param {ethers.Signer} [opts.signer] - privileged broadcaster (owner/emergency)
 * @returns {ChainConnection}
 */
export function createChainConnection({ provider, address, abi, signer } = {}) {
  const rpc = typeof provider === 'string' ? createChainProvider(provider) : provider;
  const contract = signer ? new Contract(address, abi, signer.connect(rpc)) : new Contract(address, abi, rpc);
  return new ChainConnection({ contract, address });
}

export default {
  ChainConnection,
  createChainConnection,
  createChainProvider,
  deploySmartAccount,
  intentToStruct,
  payloadDigest,
  decodeRevert,
};
