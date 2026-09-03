/**
 * aegis-vault —Base58 encoding/decoding (for address generation)
 * Extracted from NexusGenesis src/wallet/base58.js.
 */
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ALPHABET_MAP = {};
for (let i = 0; i < ALPHABET.length; i++) {
  ALPHABET_MAP[ALPHABET.charAt(i)] = i;
}

/** @param {Buffer} buffer @returns {string} */
export function base58Encode(buffer) {
  if (buffer.length === 0) return '';
  let zeros = 0;
  while (zeros < buffer.length && buffer[zeros] === 0) zeros++;
  let num = BigInt('0x' + buffer.toString('hex'));
  let encoded = '';
  while (num > 0n) {
    const remainder = num % 58n;
    num = num / 58n;
    encoded = ALPHABET[Number(remainder)] + encoded;
  }
  return '1'.repeat(zeros) + encoded;
}

/** @param {string} string @returns {Buffer} */
export function base58Decode(string) {
  if (string.length === 0) return Buffer.alloc(0);
  let zeros = 0;
  while (zeros < string.length && string.charAt(zeros) === '1') zeros++;
  let num = 0n;
  for (let i = zeros; i < string.length; i++) {
    const char = string.charAt(i);
    if (!(char in ALPHABET_MAP)) throw new Error(`Invalid Base58 character: ${char}`);
    num = num * 58n + BigInt(ALPHABET_MAP[char]);
  }
  let hex = num.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const buffer = Buffer.from(hex, 'hex');
  const prefixZeros = Buffer.alloc(zeros);
  return Buffer.concat([prefixZeros, buffer]);
}

/** @param {string} string @returns {boolean} */
export function isValidBase58(string) {
  for (let i = 0; i < string.length; i++) {
    if (!(string.charAt(i) in ALPHABET_MAP)) return false;
  }
  return true;
}

export default { base58Encode, base58Decode, isValidBase58 };