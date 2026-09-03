/**
 * Staking Contract
 * 
 * Features:
 * 1. Stake tokens
 * 2. Calculate rewards
 * 3. Unstake
 * 4. Claim rewards
 * 
 * Storage Layout:
 * 0: totalStaked
 * 1: totalRewards
 * 2: stakerCount
 */

/**
 * Generate staking contract bytecode
 * @returns {string} Contract bytecode
 */
export function generateStakingBytecode() {
  // Staking contract logic:
  // PUSH 0, STORE 0 (totalStaked)
  // PUSH 0, STORE 1 (totalRewards)
  // PUSH 0, STORE 2 (stakerCount)
  // HALT
  const bytecode = [
    0x01, 0x00,        // PUSH 0
    0x08, 0x00,        // STORE 0 (totalStaked)
    0x01, 0x00,        // PUSH 0
    0x08, 0x01,        // STORE 1 (totalRewards)
    0x01, 0x00,        // PUSH 0
    0x08, 0x02,        // STORE 2 (stakerCount)
    0x0B               // HALT
  ];
  
  return '0x' + bytecode.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate stake function bytecode
 * @param {number} amount - Stake amount
 * @returns {string} Contract bytecode
 */
export function generateStakeBytecode(amount = 100) {
  // Stake: LOAD 0, PUSH amount, ADD, STORE 0
  // LOAD 2, PUSH 1, ADD, STORE 2
  const bytecode = [
    0x07, 0x00,                 // LOAD 0 (totalStaked)
    0x01, amount & 0xFF,        // PUSH amount
    0x03,                       // ADD
    0x08, 0x00,                 // STORE 0 (totalStaked)
    0x07, 0x02,                 // LOAD 2 (stakerCount)
    0x01, 0x01,                 // PUSH 1
    0x03,                       // ADD
    0x08, 0x02,                 // STORE 2 (stakerCount)
    0x0B                        // HALT
  ];
  
  return '0x' + bytecode.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate distribute reward function bytecode
 * @param {number} reward - Reward amount
 * @returns {string} Contract bytecode
 */
export function generateDistributeRewardBytecode(reward = 10) {
  // Distribute reward: LOAD 1, PUSH reward, ADD, STORE 1
  const bytecode = [
    0x07, 0x01,                 // LOAD 1 (totalRewards)
    0x01, reward & 0xFF,        // PUSH reward
    0x03,                       // ADD
    0x08, 0x01,                 // STORE 1 (totalRewards)
    0x0B                        // HALT
  ];
  
  return '0x' + bytecode.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate unstake function bytecode
 * @param {number} amount - Unstake amount
 * @returns {string} Contract bytecode
 */
export function generateUnstakeBytecode(amount = 100) {
  // Unstake: LOAD 0, PUSH amount, SUB, STORE 0
  const bytecode = [
    0x07, 0x00,                 // LOAD 0 (totalStaked)
    0x01, amount & 0xFF,        // PUSH amount
    0x04,                       // SUB
    0x08, 0x00,                 // STORE 0 (totalStaked)
    0x0B                        // HALT
  ];
  
  return '0x' + bytecode.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Staking contract configuration
 */
export const stakingConfig = {
  name: 'NexusGenesis Staking',
  description: 'Decentralized staking system',
  minStakeAmount: 100,
  rewardRate: 0.1, // 10% APY
  contractId: 'nexus-staking-v1'
};

export default {
  generateStakingBytecode,
  generateStakeBytecode,
  generateDistributeRewardBytecode,
  generateUnstakeBytecode,
  stakingConfig
};
