import os from "node:os";
import path from "node:path";

/**
 * All state lives under one directory so the guard hook can deny the model
 * access to everything (vault, master-key fallback, materialized temp files)
 * with a single path prefix.
 */
export function vaultHome(): string {
  return process.env.SECRETS_MCP_HOME ?? path.join(os.homedir(), ".secrets-mcp");
}

export function vaultFile(): string {
  return path.join(vaultHome(), "vault.enc");
}

export function keyFile(): string {
  return path.join(vaultHome(), "master.key");
}

export function tmpDir(): string {
  return path.join(vaultHome(), "tmp");
}

export function manifestFile(): string {
  return path.join(vaultHome(), "rendered.json");
}
