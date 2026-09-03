/**
 * Token Contract - Token Contract Example
 * 
 * Features:
 * 1. Query balance (balanceOf)
 * 2. Transfer
 * 3. Query total supply (totalSupply)
 * 
 * Storage Layout:
 * 0: totalSupply
 * 1: owner balance
 * 2: recipient balance
 */

// Token contract bytecode
// Logic: implements simple token transfers
// Storage 0 = totalSupply, Storage 1 = owner, Storage 2 = recipient
export const tokenBytecode = '0x070001010308000b';

/**
 * Generate token contract bytecode
 * @param {number} totalSupply - Total supply
 * @param {number} ownerBalance - Owner balance
 * @returns {string} Contract bytecode
 */
export function generateTokenBytecode(totalSupply = 1000000, ownerBalance = 1000000) {
  // Simplified token contract:
  // PUSH totalSupply, STORE 0 (totalSupply)
  // PUSH ownerBalance, STORE 1 (owner)
  // HALT
  const bytecode = [
    0x01, totalSupply & 0xFF,        // PUSH totalSupply
    0x08, 0x00,                       // STORE 0 (totalSupply)
    0x01, ownerBalance & 0xFF,        // PUSH ownerBalance
    0x08, 0x01,                       // STORE 1 (owner balance)
    0x0B                              // HALT
  ];
  
  return '0x' + bytecode.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Token contract configuration
 */
export const tokenConfig = {
  name: 'NexusGenesis Token',
  symbol: 'NGEN',
  decimals: 8,
  totalSupply: 1000000000, // 1 billion
  contractId: 'nexus-token-v1'
};

export default {
  tokenBytecode,
  generateTokenBytecode,
  tokenConfig
};
