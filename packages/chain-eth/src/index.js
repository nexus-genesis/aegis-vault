/**
 * aegis-chain-eth —entry point
 *
 * Ethereum adapter for Aegis Vault agents: deterministic secp256k1 derivation
 * from a PQC root identity, EIP-191 signing/verification, and a spend-mode → * guardian-policy mapping so human takeover carries to EVM.
 */
import {
  CHAIN,
  ETH_CHAIN_INFO,
  deriveEthPrivateKey,
  deriveEthWallet,
  deriveEthWalletFromPQC,
  addressFromPublicKey,
  addressFromPrivateKey,
  toChecksumAddress,
  hashPersonalMessage,
  signMessage,
  verifyMessage,
  mapSpendToGuardianPolicy
} from './eth.js';
import {
  createSmartAccount,
  SmartAccount,
  SELF_ESCALATION_ACTIONS,
  ALLOWANCE_SURFACE_ACTIONS,
  DEFAULT_DAY_WINDOW_MS
} from './smart-account.js';
import {
  hashIntentDigest,
  signIntentDigest,
  verifyIntentDigest,
  addressForPrivateKey,
  signSmartAccountIntent,
  verifySmartAccountIntent
} from './canonical.js';
import { createSmartAccountClient } from './client.js';
import {
  ChainConnection,
  createChainConnection,
  createChainProvider,
  deploySmartAccount,
  intentToStruct,
  payloadDigest,
  decodeRevert,
} from './chain-connection.js';

export {
  CHAIN,
  ETH_CHAIN_INFO,
  deriveEthPrivateKey,
  deriveEthWallet,
  deriveEthWalletFromPQC,
  addressFromPublicKey,
  addressFromPrivateKey,
  toChecksumAddress,
  hashPersonalMessage,
  signMessage,
  verifyMessage,
  mapSpendToGuardianPolicy,
  createSmartAccount,
  SmartAccount,
  SELF_ESCALATION_ACTIONS,
  ALLOWANCE_SURFACE_ACTIONS,
  DEFAULT_DAY_WINDOW_MS,
  hashIntentDigest,
  signIntentDigest,
  verifyIntentDigest,
  addressForPrivateKey,
  signSmartAccountIntent,
  verifySmartAccountIntent,
  createSmartAccountClient,
  ChainConnection,
  createChainConnection,
  createChainProvider,
  deploySmartAccount,
  intentToStruct,
  payloadDigest,
  decodeRevert
};

export default {
  CHAIN,
  deriveEthWallet,
  deriveEthWalletFromPQC,
  signMessage,
  verifyMessage,
  hashIntentDigest,
  signIntentDigest,
  verifyIntentDigest,
  signSmartAccountIntent,
  verifySmartAccountIntent,
  createSmartAccountClient,
  mapSpendToGuardianPolicy,
  createSmartAccount,
  SmartAccount,
  ChainConnection,
  createChainConnection,
  createChainProvider,
  deploySmartAccount,
  intentToStruct,
  payloadDigest,
  decodeRevert
};
