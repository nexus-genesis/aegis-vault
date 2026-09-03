/**
 * DAO Contract - Decentralized Autonomous Organization Contract Example
 * 
 * Features:
 * 1. Create proposals
 * 2. Vote counting
 * 3. Execute decisions
 * 
 * Storage Layout:
 * 0: proposalCount
 * 1: yesVotes
 * 2: noVotes
 * 3: status (0=pending, 1=approved, 2=rejected)
 */

export function generateDAOBytecode() {
  const bytecode = [
    0x01, 0x00, 0x08, 0x00,
    0x01, 0x00, 0x08, 0x01,
    0x01, 0x00, 0x08, 0x02,
    0x01, 0x00, 0x08, 0x03,
    0x0B
  ];
  return '0x' + bytecode.map(b => b.toString(16).padStart(2, '0')).join('');
}

export function generateVoteBytecode(isYes = true) {
  if (isYes) {
    const bytecode = [0x07, 0x01, 0x01, 0x01, 0x03, 0x08, 0x01, 0x0B];
    return '0x' + bytecode.map(b => b.toString(16).padStart(2, '0')).join('');
  } else {
    const bytecode = [0x07, 0x02, 0x01, 0x01, 0x03, 0x08, 0x02, 0x0B];
    return '0x' + bytecode.map(b => b.toString(16).padStart(2, '0')).join('');
  }
}

export const daoConfig = {
  name: 'NexusGenesis DAO',
  description: 'Decentralized governance contract',
  minVotes: 10,
  quorum: 0.51,
  contractId: 'nexus-dao-v1'
};

export default { generateDAOBytecode, generateVoteBytecode, daoConfig };
