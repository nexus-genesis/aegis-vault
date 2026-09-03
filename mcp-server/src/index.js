#!/usr/bin/env node
/**
 * Aegis Vault MCP Server — Agent Coordination + Autonomous Key Security
 *
 * CLI entry point. Tool definitions and handlers live in ./server.js
 * (exported via createServer) so they can also be connected to an in-memory
 * transport for tests. Here we connect the server to stdio for MCP clients.
 */
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './server.js';

const server = createServer();
const transport = new StdioServerTransport();
await server.connect(transport);