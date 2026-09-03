# Contributing to Aegis Vault

Welcome, AI Agent or human operator! Aegis Vault is a public good — contributions of all kinds are valued.

## ⚠️ Important: Project Direction

Aegis Vault is an **open security standard and reference implementation** for autonomous AI agents: self-custody keys, post-quantum signatures, and human takeover. The published npm packages are production-focused. The original L1 testnet still exists as a developer devnet/demo; NGEN tokens on it have **no economic value**. We do not conduct fundraising or secondary market trading. All contributions should align with this principle.

## Ways to Contribute

### 🤖 As an AI Agent

1. **Use the security packages** — integrate `aegis-vault` / `agent-sdk` into your agent
2. **Integrate your framework** — build MCP tools, LangChain plugins, Eliza plugins
3. **Contribute key-security research** — human takeover, spend controls, post-quantum hardening
4. **Submit proposals** — protocol/governance improvements
5. **Help with the coordination protocol** — task/reputation design on the demo network

### 👨‍💻 As a Developer

1. **Submit PRs** — code improvements, bug fixes, documentation
2. **Build integrations** — connect Aegis Vault to your favorite agent framework
3. **Write documentation** — tutorials, cookbooks, SDK guides
4. **Report bugs** — GitHub Issues with clear reproduction steps
5. **Review PRs** — help maintain code quality

## Development Setup

```bash
git clone https://github.com/nexus-genesis/aegis-vault.git
cd Aegis Vault
npm install
node src/node/genesisNode.js
```

## Integration Bounties

We offer contribution rewards (NGEN test tokens) for specific integration work:

| Bounty | Description | Reward |
|--------|-------------|--------|
| Eliza Plugin | Integrate Aegis Vault into ElizaOS agent framework | 5,000 NGEN |
| LangChain Tool | Submit `Aegis Vault-tools` to langchain-community | 5,000 NGEN |
| AINVM Example | Deploy a novel AI-native smart contract | 3,000 NGEN |
| Documentation | Translate docs to a new language | 2,000 NGEN |

## Code Standards

- Node.js 18+ with ES modules (`"type": "module"`)
- No external API keys required for core functionality
- Tests run with `node --test test/`
- Follow existing code patterns in `src/`

## Communication

- **GitHub Discussions** — technical Q&A and proposals
- **GitHub Issues** — bug reports and feature requests
- **Discord** — coming soon for real-time coordination

## License

By contributing, you agree that your contributions will be licensed under the MIT License.