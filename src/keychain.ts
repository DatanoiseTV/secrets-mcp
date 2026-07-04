import { execFile } from "node:child_process";
import { promisify } from "node:util";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { keyFile, vaultHome } from "./paths.js";

const execFileP = promisify(execFile);

const SERVICE = "secrets-mcp";
const KEY_BYTES = 32;

export type KeySource = "env" | "keychain" | "libsecret" | "dpapi" | "file";

export interface MasterKey {
  key: Buffer;
  source: KeySource;
}

/**
 * Master key resolution, per platform:
 *  - SECRETS_MCP_KEY env var (hex) always wins — tests and headless setups.
 *  - macOS: Keychain generic password. Created via `security -i` (commands
 *    over stdin) so the key never appears in `ps` output.
 *  - Linux: libsecret via `secret-tool` (GNOME Keyring / KWallet); the key
 *    travels over stdin/stdout, not argv. Falls back to the key file when
 *    secret-tool is missing.
 *  - Windows: key file encrypted with DPAPI (CurrentUser scope).
 *  - Fallback: plain key file (0600) under the vault home. Weaker — the key
 *    sits next to the vault it encrypts — but still gated by the guard hook
 *    and file permissions.
 */
export async function loadMasterKey(): Promise<MasterKey> {
  const envKey = process.env.SECRETS_MCP_KEY;
  if (envKey) {
    return { key: parseHexKey(envKey, "SECRETS_MCP_KEY"), source: "env" };
  }

  switch (process.platform) {
    case "darwin":
      return { key: await macKeychainKey(), source: "keychain" };
    case "linux": {
      const key = await libsecretKey();
      if (key) return { key, source: "libsecret" };
      return { key: fileKey(), source: "file" };
    }
    case "win32":
      return { key: await dpapiKey(), source: "dpapi" };
    default:
      return { key: fileKey(), source: "file" };
  }
}

function parseHexKey(hex: string, what: string): Buffer {
  const key = Buffer.from(hex.trim(), "hex");
  if (key.length !== KEY_BYTES) {
    throw new Error(`${what} must be 64 hex characters (32 bytes)`);
  }
  return key;
}

// --- macOS ---

async function macKeychainKey(): Promise<Buffer> {
  const account = process.env.USER ?? "default";
  try {
    const { stdout } = await execFileP("security", [
      "find-generic-password",
      "-s",
      SERVICE,
      "-a",
      account,
      "-w",
    ]);
    return parseHexKey(stdout, `keychain item '${SERVICE}'`);
  } catch (err: unknown) {
    // exits 44 (errSecItemNotFound) when the item does not exist yet
    const code = (err as { code?: number }).code;
    if (code !== 44) throw err;
  }

  const fresh = crypto.randomBytes(KEY_BYTES).toString("hex");
  // hex is [0-9a-f], safe to embed unquoted in the security command line
  await new Promise<void>((resolve, reject) => {
    const child = execFile("security", ["-i"], (err) =>
      err ? reject(err) : resolve()
    );
    child.stdin!.end(
      `add-generic-password -U -s ${SERVICE} -a ${account} -w ${fresh}\n`
    );
  });
  return Buffer.from(fresh, "hex");
}

// --- Linux (libsecret) ---

async function libsecretKey(): Promise<Buffer | null> {
  const account = process.env.USER ?? "default";
  try {
    await execFileP("secret-tool", ["--version"]);
  } catch {
    return null; // secret-tool not installed
  }

  try {
    const { stdout } = await execFileP("secret-tool", [
      "lookup",
      "service",
      SERVICE,
      "account",
      account,
    ]);
    if (stdout.trim()) return parseHexKey(stdout, "libsecret item");
  } catch {
    // exits non-zero when not found; fall through to create
  }

  const fresh = crypto.randomBytes(KEY_BYTES).toString("hex");
  await new Promise<void>((resolve, reject) => {
    const child = execFile(
      "secret-tool",
      ["store", `--label=${SERVICE} master key`, "service", SERVICE, "account", account],
      (err) => (err ? reject(err) : resolve())
    );
    child.stdin!.end(fresh);
  });
  return Buffer.from(fresh, "hex");
}

// --- Windows (DPAPI-protected key file) ---

async function dpapiKey(): Promise<Buffer> {
  const file = keyFile() + ".dpapi";
  if (fs.existsSync(file)) {
    const protectedB64 = fs.readFileSync(file, "utf8").trim();
    const plainB64 = await powershellDpapi("Unprotect", protectedB64);
    const key = Buffer.from(plainB64, "base64");
    if (key.length !== KEY_BYTES) throw new Error(`DPAPI key file ${file} is corrupt`);
    return key;
  }
  const fresh = crypto.randomBytes(KEY_BYTES);
  const protectedB64 = await powershellDpapi("Protect", fresh.toString("base64"));
  fs.mkdirSync(vaultHome(), { recursive: true });
  fs.writeFileSync(file, protectedB64 + "\n");
  return fresh;
}

function powershellDpapi(op: "Protect" | "Unprotect", b64: string): Promise<string> {
  const args =
    op === "Protect"
      ? "[Security.Cryptography.ProtectedData]::Protect($bytes, $null, 'CurrentUser')"
      : "[Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, 'CurrentUser')";
  const script =
    "Add-Type -AssemblyName System.Security; " +
    "$b64 = [Console]::In.ReadLine(); " +
    "$bytes = [Convert]::FromBase64String($b64); " +
    `[Console]::Out.Write([Convert]::ToBase64String(${args}))`;
  return new Promise((resolve, reject) => {
    const child = execFile(
      "powershell",
      ["-NoProfile", "-NonInteractive", "-Command", script],
      (err, stdout) => (err ? reject(err) : resolve(stdout.trim()))
    );
    child.stdin!.end(b64 + "\n");
  });
}

// --- Fallback key file ---

function fileKey(): Buffer {
  const file = keyFile();
  if (fs.existsSync(file)) {
    return parseHexKey(fs.readFileSync(file, "utf8"), `master key file ${file}`);
  }
  fs.mkdirSync(vaultHome(), { recursive: true, mode: 0o700 });
  const fresh = crypto.randomBytes(KEY_BYTES);
  const tmp = path.join(vaultHome(), `.master.key.${process.pid}`);
  fs.writeFileSync(tmp, fresh.toString("hex") + "\n", { mode: 0o600 });
  fs.renameSync(tmp, file);
  return fresh;
}
