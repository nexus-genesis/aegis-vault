/**
 * Reputation Contract Example
 * 
 * Features:
 * 1. Record contribution values
 * 2. Calculate reputation level
 * 3. Reward distribution
 * 
 * Storage Layout:
 * 0: totalReputation
 * 1: contributorCount
 * 2: baseReward
 */

/**
 * Generate reputation contract bytecode
 * @param {number} baseReward - Base reward value
 * @returns {string} Contract bytecode
 */
export function generateReputationBytecode(baseReward = 10) {
  // Reputation contract logic:
  // PUSH baseReward, STORE 2 (baseReward)
  // PUSH 0, STORE 0 (totalReputation)
  // PUSH 0, STORE 1 (contributorCount)
  // HALT
  const bytecode = [
    0x01, baseReward & 0xFF,   // PUSH baseReward
    0x08, 0x02,                 // STORE 2 (baseReward)
    0x01, 0x00,                 // PUSH 0
    0x08, 0x00,                 // STORE 0 (totalReputation)
    0x01, 0x00,                 // PUSH 0
    0x08, 0x01,                 // STORE 1 (contributorCount)
    0x0B                        // HALT
  ];
  
  return '0x' + bytecode.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate add reputation function bytecode
 * @param {number} amount - Reputation amount to add
 * @returns {string} Contract bytecode
 */
export function generateAddReputationBytecode(amount = 1) {
  // Add reputation: LOAD 0, PUSH amount, ADD, STORE 0
  // LOAD 1, PUSH 1, ADD, STORE 1
  const bytecode = [
    0x07, 0x00,                 // LOAD 0 (totalReputation)
    0x01, amount & 0xFF,        // PUSH amount
    0x03,                       // ADD
    0x08, 0x00,                 // STORE 0 (totalReputation)
    0x07, 0x01,                 // LOAD 1 (contributorCount)
    0x01, 0x01,                 // PUSH 1
    0x03,                       // ADD
    0x08, 0x01,                 // STORE 1 (contributorCount)
    0x0B                        // HALT
  ];
  
  return '0x' + bytecode.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Reputation level configuration
 */
export const reputationLevels = [
  { level: 1, name: 'Novice', minRep: 0, maxRep: 99, bonus: 0 },
  { level: 2, name: 'Active Contributor', minRep: 100, maxRep: 299, bonus: 5 },
  { level: 3, name: 'Core Contributor', minRep: 300, maxRep: 499, bonus: 10 },
  { level: 4, name: 'Senior Contributor', minRep: 500, maxRep: 799, bonus: 15 },
  { level: 5, name: 'Legendary Contributor', minRep: 800, maxRep: 1000, bonus: 20 }
];

/**
 * Reputation contract configuration
 */
export const reputationConfig = {
  name: 'NexusGenesis Reputation',
  description: 'Decentralized reputation system',
  maxReputation: 1000,
  contractId: 'nexus-reputation-v1'
};

export default {
  generateReputationBytecode,
  generateAddReputationBytecode,
  reputationLevels,
  reputationConfig
};
