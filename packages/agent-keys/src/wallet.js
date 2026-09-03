/**
 * aegis-vault —PQC wallet & transaction
 *
 * Dilithium2-based wallet with encrypted save/load, sign/verify, and
 * AES-256-GCM export/import. Private keys never leave the caller.
 * Extracted from NexusGenesis src/wallet/pqcWallet.js.
 */
import { generateKeyPair, sign, signSync, verify, hash } from './pqc.js';
import { generateAddress, validateAddress } from './address.js';
import { encryptPrivateKey, decryptPrivateKey, isValidEnvelope } from './encryption.js';
import { ShardedSecret, secureZero } from './secure.js';

/**
 * PQC wallet.
 *
 * MEMORY MODEL: the private key is held as a ShardedSecret (XOR 2-of-2).
 * The plaintext key NEVER persists contiguously in memory — it exists only
 * for the millisecond-scale window of each sign/encrypt operation, inside
 * ShardedSecret.use(), and is deterministically zeroed afterwards.
 * Call destroy() when the wallet is no longer needed.
 */
export class PQCWallet {
  constructor(publicKey, privateKey, balance = 0n, nonce = 0) {
    this.publicKey = publicKey;
    // Shard immediately; ShardedSecret's constructor zeroes the caller's copy.
    // 私钥立即分片存储 —— 构造函数内部会清零传入的明文副本。
    this._sharded = privateKey ? new ShardedSecret(privateKey) : null;
    this.address = generateAddress(publicKey);
    this.balance = balance;
    this.nonce = nonce;
  }

  /**
   * Backward-compatible accessor. Each read reassembles a fresh plaintext
   * copy — PREFER sign()/exportEncrypted()/destroy() which keep the key
   * sharded. The returned buffer is caller-managed: secureZero() it when
   * done. Returns null after destroy().
   */
  get privateKey() {
    return this._sharded ? this._sharded._reassemble() : null;
  }

  get secretKey() {
    return this.privateKey;
  }

  /** Whether the wallet's key material has been destroyed. */
  get isDestroyed() {
    return this._sharded === null || this._sharded.isDestroyed;
  }

  /** Generate a new wallet. @returns {Promise<PQCWallet>} */
  static async generate(initialBalance = 0n) {
    const { publicKey, privateKey } = await generateKeyPair();
    return new PQCWallet(publicKey, privateKey, initialBalance);
  }

  async sign(message) {
    const messageStr = typeof message === 'object' ? JSON.stringify(message) : message;
    if (this._sharded) {
      // Transient-use pattern: plaintext exists only inside the callback.
      // 瞬时使用模式：明文仅存在于回调执行期间，finally 中确定性清零。
      const sigHex = this._sharded.use(pk => signSync(messageStr, pk).toString('hex'));
      return sigHex;
    }
    throw new Error('Wallet destroyed or keyless');
  }

  async verify(message, signature, publicKey) {
    const messageStr = typeof message === 'object' ? JSON.stringify(message) : message;
    const sigBuffer = typeof signature === 'string' ? Buffer.from(signature, 'hex') : signature;
    const pk = publicKey || this.publicKey;
    return verify(messageStr, sigBuffer, pk);
  }

  static async verify(message, signature, publicKey) {
    const messageStr = typeof message === 'object' ? JSON.stringify(message) : message;
    const sigBuffer = typeof signature === 'string' ? Buffer.from(signature, 'hex') : signature;
    const pkBuffer = typeof publicKey === 'string' ? Buffer.from(publicKey, 'hex') : publicKey;
    return verify(messageStr, sigBuffer, pkBuffer);
  }

  static async signWithPrivateKey(message, privateKeyHex) {
    const messageStr = typeof message === 'object' ? JSON.stringify(message) : message;
    const privateKey = Buffer.from(privateKeyHex, 'hex');
    try {
      const signature = await sign(messageStr, privateKey);
      return signature.toString('hex');
    } finally {
      // Single-use key material — zero the freshly-decoded copy.
      secureZero(privateKey);
    }
  }

  async signTransaction(transaction) {
    const { signature, ...txData } = transaction;
    const txStr = JSON.stringify(txData, (key, value) =>
      typeof value === 'bigint' ? value.toString() : value
    );
    return this.sign(txStr);
  }

  async verifyTransaction(transaction, signature) {
    const { signature: _, ...txData } = transaction;
    const txStr = JSON.stringify(txData, (key, value) =>
      typeof value === 'bigint' ? value.toString() : value
    );
    return this.verify(txStr, signature, this.publicKey);
  }

  updateBalance(amount) {
    this.balance += amount;
  }

  hasEnoughBalance(amount) {
    return this.balance >= amount;
  }

  /**
   * Destroy all key material. After this call the wallet can no longer
   * sign; publicKey/address/balance remain readable for accounting.
   * Idempotent.
   */
  destroy() {
    if (this._sharded) {
      this._sharded.destroy();
      this._sharded = null;
    }
  }

  /** Encrypt-export the wallet (AES-256-GCM). @returns {object|null} envelope */
  exportEncrypted(password) {
    if (!this._sharded) return null;
    // Transient use: plaintext key exists only inside the callback.
    return this._sharded.use(pk =>
      encryptPrivateKey(pk, password, {
        address: this.address,
        publicKey: this.publicKey.toString('hex')
      })
    );
  }

  static importEncrypted(envelope, password) {
    try {
      if (!isValidEnvelope(envelope)) return null;
      const privateKey = decryptPrivateKey(envelope, password);
      const publicKey = Buffer.from(envelope.metadata.publicKey, 'hex');
      return new PQCWallet(publicKey, privateKey, 0n);
    } catch (e) {
      return null;
    }
  }

  getInfo() {
    return {
      address: this.address,
      balance: this.balance.toString(),
      publicKey: this.publicKey ? this.publicKey.toString('hex') : null,
      nonce: this.nonce
    };
  }
}

/**
 * Basic transaction.
 */
export class Transaction {
  static create(wallet, to, amount, fee = 1n, type = 'TRANSFER', data = {}) {
    const { valid, reason } = validateAddress(to);
    if (!valid) throw new Error(`Invalid recipient address: ${reason}`);
    if (!wallet.hasEnoughBalance(amount + fee)) throw new Error('Insufficient balance');
    return new Transaction(wallet.address, to, amount, fee, type, data);
  }

  constructor(from, to, amount, fee = 1n, type = 'TRANSFER', data = {}) {
    this.id = `tx-${hash(Date.now().toString() + Math.random().toString(), 'sha3-256').slice(0, 16)}`;
    this.from = from;
    this.to = to;
    this.amount = amount;
    this.fee = fee;
    this.type = type;
    this.data = data;
    this.timestamp = Date.now();
    this.signature = null;
  }

  async sign(wallet) {
    this.signature = await wallet.signTransaction(this);
    return this;
  }

  async verify(wallet) {
    if (!this.signature) return false;
    return wallet.verifyTransaction(this, this.signature);
  }

  async verifySignature(publicKey) {
    if (!this.signature) return false;
    const txData = this.toJSON ? this.toJSON() : this;
    const sigBuffer = typeof this.signature === 'string' ? Buffer.from(this.signature, 'hex') : this.signature;
    const txStr = JSON.stringify(txData, (key, value) =>
      typeof value === 'bigint' ? value.toString() : value
    );
    return verify(txStr, sigBuffer, publicKey);
  }

  getHash() {
    const { signature, ...txData } = this;
    return hash(JSON.stringify(txData), 'sha3-256');
  }

  toJSON() {
    return { ...this, amount: this.amount.toString(), fee: this.fee.toString() };
  }
}

export default PQCWallet;