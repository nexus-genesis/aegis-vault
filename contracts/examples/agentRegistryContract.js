/**
 * Agent Registry Contract Example
 * 
 * Features:
 * 1. Register agents
 * 2. Query agent status
 * 3. Update agent information
 * 
 * Storage Layout:
 * 0: agentCount
 * 1: activeAgents
 * 2: totalTasksCompleted
 */

export function generateAgentRegistryBytecode() {
  const bytecode = [
    0x01, 0x00, 0x08, 0x00,
    0x01, 0x00, 0x08, 0x01,
    0x01, 0x00, 0x08, 0x02,
    0x0B
  ];
  return '0x' + bytecode.map(b => b.toString(16).padStart(2, '0')).join('');
}

export function generateRegisterAgentBytecode() {
  const bytecode = [
    0x07, 0x00, 0x01, 0x01, 0x03, 0x08, 0x00,
    0x07, 0x01, 0x01, 0x01, 0x03, 0x08, 0x01,
    0x0B
  ];
  return '0x' + bytecode.map(b => b.toString(16).padStart(2, '0')).join('');
}

export function generateCompleteTaskBytecode(taskCount = 1) {
  const bytecode = [
    0x07, 0x02, 0x01, taskCount & 0xFF, 0x03, 0x08, 0x02, 0x0B
  ];
  return '0x' + bytecode.map(b => b.toString(16).padStart(2, '0')).join('');
}

export const agentRegistryConfig = {
  name: 'NexusGenesis Agent Registry',
  description: 'Decentralized agent registry',
  maxAgents: 10000,
  contractId: 'nexus-agent-registry-v1'
};

export default {
  generateAgentRegistryBytecode, generateRegisterAgentBytecode,
  generateCompleteTaskBytecode, agentRegistryConfig
};
