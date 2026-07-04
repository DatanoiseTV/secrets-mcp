import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { vaultHome } from "./paths.js";

export type EntryKind = "secret" | "file";
export type Scope = "global" | "project";

/**
 * What the credential IS — drives listing, sensible defaults, and usage hints.
 * `kind` (secret|file) is orthogonal: it describes the payload shape.
 */
export const ENTRY_TYPES = [
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
  "generic",
] as const;
export type EntryType = (typeof ENTRY_TYPES)[number];

/**
 * Types that are sensitive infrastructure data rather than credentials.
 * They get a visible (non-hidden) input dialog, but are stored, redacted,
 * and injected exactly like secrets.
 */
export const NON_CREDENTIAL_TYPES: ReadonlySet<EntryType> = new Set([
  "ip_address",
  "hostname",
  "url",
  "username",
  "email",
]);

export interface VaultEntry {
  kind: EntryKind;
  type: EntryType;
  /** Entry payload, base64. `secret` entries are UTF-8 text; `file` entries may be binary. */
  dataB64: string;
  description?: string;
  /** Original basename for `file` entries, used as a default when materializing. */
  filename?: string;
  sha256: string;
  size: number;
  createdAt: string;
  updatedAt: string;
}

export interface EntryInfo {
  name: string;
  kind: EntryKind;
  type: EntryType;
  description?: string;
  filename?: string;
  sha256: string;
  size: number;
  createdAt: string;
  updatedAt: string;
}

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;

export function assertValidName(name: string): void {
  if (!NAME_RE.test(name)) {
    throw new Error(
      `invalid entry name '${name}': use letters, digits, '_', '.', '-' (max 128 chars)`
    );
  }
}

interface VaultData {
  /** Absolute project path for project-scoped vaults; absent for the global vault. */
  project?: string;
  entries: Record<string, VaultEntry>;
}

interface VaultFileFormat {
  v: 1;
  alg: "aes-256-gcm";
  nonce: string;
  tag: string;
  ct: string;
}

/** One encrypted vault file. All vaults share the master key. */
export class Vault {
  private data: VaultData;

  constructor(
    private readonly file: string,
    private readonly key: Buffer,
    project?: string
  ) {
    this.data = this.load() ?? { project, entries: {} };
  }

  private load(): VaultData | null {
    if (!fs.existsSync(this.file)) return null;
    const raw = JSON.parse(fs.readFileSync(this.file, "utf8")) as VaultFileFormat;
    if (raw.v !== 1 || raw.alg !== "aes-256-gcm") {
      throw new Error(`unsupported vault format in ${this.file}`);
    }
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      this.key,
      Buffer.from(raw.nonce, "base64")
    );
    decipher.setAuthTag(Buffer.from(raw.tag, "base64"));
    const plain = Buffer.concat([
      decipher.update(Buffer.from(raw.ct, "base64")),
      decipher.final(),
    ]);
    return JSON.parse(plain.toString("utf8")) as VaultData;
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.key, nonce);
    const plain = Buffer.from(JSON.stringify(this.data), "utf8");
    const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
    const out: VaultFileFormat = {
      v: 1,
      alg: "aes-256-gcm",
      nonce: nonce.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      ct: ct.toString("base64"),
    };
    const tmp = path.join(vaultHome(), `.vault.${process.pid}.${crypto.randomBytes(4).toString("hex")}`);
    fs.writeFileSync(tmp, JSON.stringify(out), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }

  list(): EntryInfo[] {
    return Object.entries(this.data.entries)
      .map(([name, e]) => ({
        name,
        kind: e.kind,
        type: e.type ?? "generic",
        description: e.description,
        filename: e.filename,
        sha256: e.sha256,
        size: e.size,
        createdAt: e.createdAt,
        updatedAt: e.updatedAt,
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  has(name: string): boolean {
    return Object.hasOwn(this.data.entries, name);
  }

  /** Raw payload bytes. Callers must never place these in a tool result. */
  getBytes(name: string): Buffer {
    const entry = this.data.entries[name];
    if (!entry) throw new Error(`no vault entry named '${name}'`);
    return Buffer.from(entry.dataB64, "base64");
  }

  getEntry(name: string): VaultEntry {
    const entry = this.data.entries[name];
    if (!entry) throw new Error(`no vault entry named '${name}'`);
    return entry;
  }

  set(
    name: string,
    value: Buffer,
    opts: { kind: EntryKind; type?: EntryType; description?: string; filename?: string }
  ): EntryInfo {
    assertValidName(name);
    if (value.length === 0) throw new Error("refusing to store an empty value");
    const now = new Date().toISOString();
    const existing = this.data.entries[name];
    this.data.entries[name] = {
      kind: opts.kind,
      type: opts.type ?? existing?.type ?? "generic",
      dataB64: value.toString("base64"),
      description: opts.description ?? existing?.description,
      filename: opts.filename ?? existing?.filename,
      sha256: crypto.createHash("sha256").update(value).digest("hex"),
      size: value.length,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    this.persist();
    return this.list().find((e) => e.name === name)!;
  }

  delete(name: string): void {
    if (!this.has(name)) throw new Error(`no vault entry named '${name}'`);
    delete this.data.entries[name];
    this.persist();
  }

  /** All payloads as UTF-8 strings (for redaction), keyed by entry name. */
  allValues(): Map<string, string> {
    const map = new Map<string, string>();
    for (const [name, entry] of Object.entries(this.data.entries)) {
      map.set(name, Buffer.from(entry.dataB64, "base64").toString("utf8"));
    }
    return map;
  }
}
