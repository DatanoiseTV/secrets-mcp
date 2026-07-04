#!/usr/bin/env node
import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);

// src/cli.ts
import fs3 from "node:fs";
import path5 from "node:path";
import readline from "node:readline";
import { Writable } from "node:stream";

// src/store.ts
import crypto3 from "node:crypto";
import path4 from "node:path";

// src/keychain.ts
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import crypto from "node:crypto";
import fs from "node:fs";
import path2 from "node:path";

// src/paths.ts
import os from "node:os";
import path from "node:path";
function vaultHome() {
  return process.env.SECRETS_MCP_HOME ?? path.join(os.homedir(), ".secrets-mcp");
}
function vaultFile() {
  return path.join(vaultHome(), "vault.enc");
}
function keyFile() {
  return path.join(vaultHome(), "master.key");
}

// src/keychain.ts
var execFileP = promisify(execFile);
var SERVICE = "secrets-mcp";
var KEY_BYTES = 32;
async function loadMasterKey() {
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
function parseHexKey(hex, what) {
  const key = Buffer.from(hex.trim(), "hex");
  if (key.length !== KEY_BYTES) {
    throw new Error(`${what} must be 64 hex characters (32 bytes)`);
  }
  return key;
}
async function macKeychainKey() {
  const account = process.env.USER ?? "default";
  try {
    const { stdout } = await execFileP("security", [
      "find-generic-password",
      "-s",
      SERVICE,
      "-a",
      account,
      "-w"
    ]);
    return parseHexKey(stdout, `keychain item '${SERVICE}'`);
  } catch (err) {
    const code = err.code;
    if (code !== 44) throw err;
  }
  const fresh = crypto.randomBytes(KEY_BYTES).toString("hex");
  await new Promise((resolve, reject) => {
    const child = execFile(
      "security",
      ["-i"],
      (err) => err ? reject(err) : resolve()
    );
    child.stdin.end(
      `add-generic-password -U -s ${SERVICE} -a ${account} -w ${fresh}
`
    );
  });
  return Buffer.from(fresh, "hex");
}
async function libsecretKey() {
  const account = process.env.USER ?? "default";
  try {
    await execFileP("secret-tool", ["--version"]);
  } catch {
    return null;
  }
  try {
    const { stdout } = await execFileP("secret-tool", [
      "lookup",
      "service",
      SERVICE,
      "account",
      account
    ]);
    if (stdout.trim()) return parseHexKey(stdout, "libsecret item");
  } catch {
  }
  const fresh = crypto.randomBytes(KEY_BYTES).toString("hex");
  await new Promise((resolve, reject) => {
    const child = execFile(
      "secret-tool",
      ["store", `--label=${SERVICE} master key`, "service", SERVICE, "account", account],
      (err) => err ? reject(err) : resolve()
    );
    child.stdin.end(fresh);
  });
  return Buffer.from(fresh, "hex");
}
async function dpapiKey() {
  const file = keyFile() + ".dpapi";
  if (fs.existsSync(file)) {
    const protectedB642 = fs.readFileSync(file, "utf8").trim();
    const plainB64 = await powershellDpapi("Unprotect", protectedB642);
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
function powershellDpapi(op, b64) {
  const args = op === "Protect" ? "[Security.Cryptography.ProtectedData]::Protect($bytes, $null, 'CurrentUser')" : "[Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, 'CurrentUser')";
  const script = `Add-Type -AssemblyName System.Security; $b64 = [Console]::In.ReadLine(); $bytes = [Convert]::FromBase64String($b64); [Console]::Out.Write([Convert]::ToBase64String(${args}))`;
  return new Promise((resolve, reject) => {
    const child = execFile(
      "powershell",
      ["-NoProfile", "-NonInteractive", "-Command", script],
      (err, stdout) => err ? reject(err) : resolve(stdout.trim())
    );
    child.stdin.end(b64 + "\n");
  });
}
function fileKey() {
  const file = keyFile();
  if (fs.existsSync(file)) {
    return parseHexKey(fs.readFileSync(file, "utf8"), `master key file ${file}`);
  }
  fs.mkdirSync(vaultHome(), { recursive: true, mode: 448 });
  const fresh = crypto.randomBytes(KEY_BYTES);
  const tmp = path2.join(vaultHome(), `.master.key.${process.pid}`);
  fs.writeFileSync(tmp, fresh.toString("hex") + "\n", { mode: 384 });
  fs.renameSync(tmp, file);
  return fresh;
}

// src/vault.ts
import crypto2 from "node:crypto";
import fs2 from "node:fs";
import path3 from "node:path";
var ENTRY_TYPES = [
  "password",
  "api_key",
  "bearer_token",
  "oauth_token",
  "ssh_private_key",
  "ssh_public_key",
  "tls_certificate",
  "tls_private_key",
  "pkcs12_bundle",
  "gpg_key",
  "connection_string",
  "webhook_secret",
  "totp_seed",
  "ip_address",
  "hostname",
  "url",
  "username",
  "email",
  "generic"
];
var NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
function assertValidName(name) {
  if (!NAME_RE.test(name)) {
    throw new Error(
      `invalid entry name '${name}': use letters, digits, '_', '.', '-' (max 128 chars)`
    );
  }
}
var Vault = class {
  constructor(file, key, project) {
    this.file = file;
    this.key = key;
    this.data = this.load() ?? { project, entries: {} };
  }
  file;
  key;
  data;
  load() {
    if (!fs2.existsSync(this.file)) return null;
    const raw = JSON.parse(fs2.readFileSync(this.file, "utf8"));
    if (raw.v !== 1 || raw.alg !== "aes-256-gcm") {
      throw new Error(`unsupported vault format in ${this.file}`);
    }
    const decipher = crypto2.createDecipheriv(
      "aes-256-gcm",
      this.key,
      Buffer.from(raw.nonce, "base64")
    );
    decipher.setAuthTag(Buffer.from(raw.tag, "base64"));
    const plain = Buffer.concat([
      decipher.update(Buffer.from(raw.ct, "base64")),
      decipher.final()
    ]);
    return JSON.parse(plain.toString("utf8"));
  }
  persist() {
    fs2.mkdirSync(path3.dirname(this.file), { recursive: true, mode: 448 });
    const nonce = crypto2.randomBytes(12);
    const cipher = crypto2.createCipheriv("aes-256-gcm", this.key, nonce);
    const plain = Buffer.from(JSON.stringify(this.data), "utf8");
    const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
    const out = {
      v: 1,
      alg: "aes-256-gcm",
      nonce: nonce.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      ct: ct.toString("base64")
    };
    const tmp = path3.join(vaultHome(), `.vault.${process.pid}.${crypto2.randomBytes(4).toString("hex")}`);
    fs2.writeFileSync(tmp, JSON.stringify(out), { mode: 384 });
    fs2.renameSync(tmp, this.file);
  }
  list() {
    return Object.entries(this.data.entries).map(([name, e]) => ({
      name,
      kind: e.kind,
      type: e.type ?? "generic",
      description: e.description,
      filename: e.filename,
      sha256: e.sha256,
      size: e.size,
      createdAt: e.createdAt,
      updatedAt: e.updatedAt
    })).sort((a, b) => a.name.localeCompare(b.name));
  }
  has(name) {
    return Object.hasOwn(this.data.entries, name);
  }
  /** Raw payload bytes. Callers must never place these in a tool result. */
  getBytes(name) {
    const entry = this.data.entries[name];
    if (!entry) throw new Error(`no vault entry named '${name}'`);
    return Buffer.from(entry.dataB64, "base64");
  }
  getEntry(name) {
    const entry = this.data.entries[name];
    if (!entry) throw new Error(`no vault entry named '${name}'`);
    return entry;
  }
  set(name, value, opts) {
    assertValidName(name);
    if (value.length === 0) throw new Error("refusing to store an empty value");
    const now = (/* @__PURE__ */ new Date()).toISOString();
    const existing = this.data.entries[name];
    this.data.entries[name] = {
      kind: opts.kind,
      type: opts.type ?? existing?.type ?? "generic",
      dataB64: value.toString("base64"),
      description: opts.description ?? existing?.description,
      filename: opts.filename ?? existing?.filename,
      sha256: crypto2.createHash("sha256").update(value).digest("hex"),
      size: value.length,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now
    };
    this.persist();
    return this.list().find((e) => e.name === name);
  }
  delete(name) {
    if (!this.has(name)) throw new Error(`no vault entry named '${name}'`);
    delete this.data.entries[name];
    this.persist();
  }
  /** All payloads as UTF-8 strings (for redaction), keyed by entry name. */
  allValues() {
    const map = /* @__PURE__ */ new Map();
    for (const [name, entry] of Object.entries(this.data.entries)) {
      map.set(name, Buffer.from(entry.dataB64, "base64").toString("utf8"));
    }
    return map;
  }
};

// src/store.ts
var Store = class _Store {
  constructor(global, project, projectDir, keySource) {
    this.global = global;
    this.project = project;
    this.projectDir = projectDir;
    this.keySource = keySource;
  }
  global;
  project;
  projectDir;
  keySource;
  static async open(projectDir) {
    const master = await loadMasterKey();
    const abs = path4.resolve(projectDir);
    const hash = crypto3.createHash("sha256").update(abs).digest("hex").slice(0, 16);
    const projectVaultFile = path4.join(vaultHome(), "projects", `${hash}.enc`);
    return new _Store(
      new Vault(vaultFile(), master.key),
      new Vault(projectVaultFile, master.key, abs),
      abs,
      master.source
    );
  }
  vaultFor(scope) {
    return scope === "project" ? this.project : this.global;
  }
  /** Project-first, then global. Throws if the name exists in neither. */
  resolve(name) {
    if (this.project.has(name)) return { vault: this.project, scope: "project" };
    if (this.global.has(name)) return { vault: this.global, scope: "global" };
    throw new Error(
      `no vault entry named '${name}' in project (${this.projectDir}) or global scope`
    );
  }
  list() {
    return [
      ...this.project.list().map((e) => ({ ...e, scope: "project" })),
      ...this.global.list().map((e) => ({ ...e, scope: "global" }))
    ];
  }
  /** Union of all values in both scopes, for redaction. Project shadows global on name clash. */
  allValues() {
    const map = /* @__PURE__ */ new Map();
    for (const [name, value] of this.global.allValues()) map.set(`global:${name}`, value);
    for (const [name, value] of this.project.allValues()) map.set(`project:${name}`, value);
    return map;
  }
};

// src/cli.ts
function parseArgs(argv) {
  const positional = [];
  const flags = /* @__PURE__ */ new Map();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq !== -1) {
        flags.set(a.slice(2, eq), a.slice(eq + 1));
      } else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        flags.set(a.slice(2), argv[++i]);
      } else {
        flags.set(a.slice(2), true);
      }
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}
function usage() {
  console.log(`secrets-vault \u2014 encrypted credential store for secrets-mcp

Usage:
  secrets-vault list                         [--project <dir>]
  secrets-vault set <name>                   [--scope global|project] [--type <type>]
                                             [--description <text>] [--project <dir>]
                                             (value read from hidden prompt, or piped stdin)
  secrets-vault import <name> --file <path>  [--scope ...] [--type ...] [--description ...]
  secrets-vault rm <name>                    [--scope global|project]
  secrets-vault types

Scope defaults to 'project' (resolved from --project or the current directory).
Types: ${ENTRY_TYPES.join(", ")}`);
  process.exit(1);
}
async function readValue(name) {
  if (!process.stdin.isTTY) {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    return Buffer.concat(chunks).toString("utf8").replace(/\n$/, "");
  }
  const muted = new Writable({ write: (_c, _e, cb) => cb() });
  const rl = readline.createInterface({ input: process.stdin, output: muted, terminal: true });
  process.stderr.write(`Value for '${name}' (input hidden): `);
  const value = await new Promise((resolve) => rl.question("", resolve));
  rl.close();
  process.stderr.write("\n");
  return value;
}
function scopeOf(args) {
  const s = args.flags.get("scope") ?? "project";
  if (s !== "global" && s !== "project") {
    console.error(`invalid --scope '${s}' (use global or project)`);
    process.exit(1);
  }
  return s;
}
function typeOf(args) {
  const t = args.flags.get("type");
  if (t === void 0 || t === true) return void 0;
  if (!ENTRY_TYPES.includes(t)) {
    console.error(`invalid --type '${t}'; run 'secrets-vault types' for the list`);
    process.exit(1);
  }
  return t;
}
function str(args, flag) {
  const v = args.flags.get(flag);
  return typeof v === "string" ? v : void 0;
}
async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [command, name] = args.positional;
  if (!command) usage();
  if (command === "types") {
    console.log(ENTRY_TYPES.join("\n"));
    return;
  }
  const projectDir = str(args, "project") ?? process.env.SECRETS_MCP_PROJECT ?? process.cwd();
  const store = await Store.open(projectDir);
  switch (command) {
    case "list": {
      const entries = store.list();
      if (entries.length === 0) {
        console.log(`vault is empty (project: ${store.projectDir})`);
        return;
      }
      for (const e of entries) {
        const desc = e.description ? `  # ${e.description}` : "";
        console.log(
          `${e.scope.padEnd(7)} ${e.name.padEnd(32)} ${e.type.padEnd(16)} ${e.kind.padEnd(6)} ${String(e.size).padStart(8)}B${desc}`
        );
      }
      return;
    }
    case "set": {
      if (!name) usage();
      const value = await readValue(name);
      if (!value) {
        console.error("empty value \u2014 nothing stored");
        process.exit(1);
      }
      const info = store.vaultFor(scopeOf(args)).set(name, Buffer.from(value, "utf8"), {
        kind: "secret",
        type: typeOf(args),
        description: str(args, "description")
      });
      console.log(`stored '${name}' (${scopeOf(args)}, ${info.type}, ${info.size} bytes)`);
      return;
    }
    case "import": {
      if (!name) usage();
      const file = str(args, "file");
      if (!file) usage();
      const abs = path5.resolve(file);
      const info = store.vaultFor(scopeOf(args)).set(name, fs3.readFileSync(abs), {
        kind: "file",
        type: typeOf(args),
        description: str(args, "description"),
        filename: path5.basename(abs)
      });
      console.log(`imported '${name}' from ${abs} (${scopeOf(args)}, ${info.type}, ${info.size} bytes)`);
      return;
    }
    case "rm": {
      if (!name) usage();
      store.vaultFor(scopeOf(args)).delete(name);
      console.log(`deleted '${name}' (${scopeOf(args)})`);
      return;
    }
    default:
      usage();
  }
}
main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
