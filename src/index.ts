#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createRequire } from "node:module";
import { buildServer } from "./server.js";
import { Store } from "./store.js";

const require = createRequire(import.meta.url);
const { version } = require("../package.json") as { version: string };

async function main(): Promise<void> {
  const projectDir = process.env.SECRETS_MCP_PROJECT ?? process.cwd();
  const store = await Store.open(projectDir);
  // stderr only — stdout is the MCP transport
  console.error(
    `secrets-mcp ${version}: project=${store.projectDir} keySource=${store.keySource}`
  );
  const server = buildServer(store, version);
  await server.connect(new StdioServerTransport());
}

main().catch((err) => {
  console.error(`secrets-mcp failed to start: ${err instanceof Error ? err.message : err}`);
  process.exit(1);
});
