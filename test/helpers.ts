import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/** Isolated vault home + env master key so tests never touch the real keychain or vault. */
export function isolatedEnv(): { home: string; cleanup: () => void } {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "secrets-mcp-test-"));
  process.env.SECRETS_MCP_HOME = home;
  process.env.SECRETS_MCP_KEY = crypto.randomBytes(32).toString("hex");
  return {
    home,
    cleanup: () => {
      fs.rmSync(home, { recursive: true, force: true });
      delete process.env.SECRETS_MCP_HOME;
      delete process.env.SECRETS_MCP_KEY;
    },
  };
}
