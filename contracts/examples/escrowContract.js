/**
 * Escrow Contract Example
 * 
 * Features:
 * 1. Create escrow
 * 2. Confirm delivery
 * 3. Release funds
 * 
 * Storage Layout:
 * 0: escrowAmount
 * 1: status (0=pending, 1=confirmed, 2=released)
 * 2: confirmations
 */

/**
 * Generate escrow contract bytecode
 * @param {number} amount - Escrow amount
 * @returns {string} Contract bytecode
 */
export function generateEscrowBytecode(amount = 1000) {
  // Escrow contract logic:
  // PUSH amount, STORE 0 (escrowAmount)
  // PUSH 0, STORE 1 (status)
  // PUSH 0, STORE 2 (confirmations)
  // HALT
  const bytecode = [
    0x01, amount & 0xFF,        // PUSH amount
    0x08, 0x00,                 // STORE 0 (escrowAmount)
    0x01, 0x00,                 // PUSH 0
    0x08, 0x01,                 // STORE 1 (status)
    0x01, 0x00,                 // PUSH 0
    0x08, 0x02,                 // STORE 2 (confirmations)
    0x0B                        // HALT
  ];
  
  return '0x' + bytecode.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate confirm delivery function bytecode
 * @returns {string} Contract bytecode
 */
export function generateConfirmBytecode() {
  // Confirm delivery: LOAD 2, PUSH 1, ADD, STORE 2
  // LOAD 1, PUSH 1, STORE 1
  const bytecode = [
    0x07, 0x02,                 // LOAD 2 (confirmations)
    0x01, 0x01,                 // PUSH 1
    0x03,                       // ADD
    0x08, 0x02,                 // STORE 2 (confirmations)
    0x01, 0x01,                 // PUSH 1
    0x08, 0x01,                 // STORE 1 (status = confirmed)
    0x0B                        // HALT
  ];
  
  return '0x' + bytecode.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate release funds function bytecode
 * @returns {string} Contract bytecode
 */
export function generateReleaseBytecode() {
  // Release funds: LOAD 0, PUSH 0, STORE 0 (clear)
  // PUSH 2, STORE 1 (status = released)
  const bytecode = [
    0x01, 0x00,                 // PUSH 0
    0x08, 0x00,                 // STORE 0 (escrowAmount = 0)
    0x01, 0x02,                 // PUSH 2
    0x08, 0x01,                 // STORE 1 (status = released)
    0x0B                        // HALT
  ];
  
  return '0x' + bytecode.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Escrow contract configuration
 */
export const escrowConfig = {
  name: 'NexusGenesis Escrow',
  description: 'Decentralized escrow service',
  minConfirmations: 2,
  contractId: 'nexus-escrow-v1'
};

export default {
  generateEscrowBytecode,
  generateConfirmBytecode,
  generateReleaseBytecode,
  escrowConfig
};
