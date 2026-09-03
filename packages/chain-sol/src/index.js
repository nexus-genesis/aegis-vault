/**
 * aegis-chain-sol —entry point
 */
import {
  CHAIN,
  SOL_CHAIN_INFO,
  deriveSolPrivateKey,
  deriveSolWallet,
  deriveSolWalletFromPQC,
  addressFromPublicKey,
  publicKeyFromAddress,
  signMessage,
  verifyMessage
} from './sol.js';

export {
  CHAIN,
  SOL_CHAIN_INFO,
  deriveSolPrivateKey,
  deriveSolWallet,
  deriveSolWalletFromPQC,
  addressFromPublicKey,
  publicKeyFromAddress,
  signMessage,
  verifyMessage
};

export default {
  CHAIN,
  deriveSolWallet,
  deriveSolWalletFromPQC,
  signMessage,
  verifyMessage
};