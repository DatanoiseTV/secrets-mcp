import crypto from "node:crypto";
import path from "node:path";
import { loadMasterKey } from "./keychain.js";
import { vaultFile, vaultHome } from "./paths.js";
import { Vault, type EntryInfo, type Scope } from "./vault.js";

export interface ScopedEntryInfo extends EntryInfo {
  scope: Scope;
}

export interface Resolved {
  vault: Vault;
  scope: Scope;
}

/**
 * Two-level store: one global vault plus a per-project vault keyed by the
 * project directory. Project vaults live centrally under
 * ~/.secrets-mcp/projects/ (never inside the repo), so secrets cannot be
 * committed and the guard hook covers them with the same path prefix.
 *
 * Writes go to an explicit scope. Reads resolve project-first, then global.
 */
export class Store {
  private constructor(
    readonly global: Vault,
    readonly project: Vault,
    readonly projectDir: string,
    readonly keySource: string
  ) {}

  static async open(projectDir: string): Promise<Store> {
    const master = await loadMasterKey();
    const abs = path.resolve(projectDir);
    const hash = crypto.createHash("sha256").update(abs).digest("hex").slice(0, 16);
    const projectVaultFile = path.join(vaultHome(), "projects", `${hash}.enc`);
    return new Store(
      new Vault(vaultFile(), master.key),
      new Vault(projectVaultFile, master.key, abs),
      abs,
      master.source
    );
  }

  vaultFor(scope: Scope): Vault {
    return scope === "project" ? this.project : this.global;
  }

  /** Project-first, then global. Throws if the name exists in neither. */
  resolve(name: string): Resolved {
    if (this.project.has(name)) return { vault: this.project, scope: "project" };
    if (this.global.has(name)) return { vault: this.global, scope: "global" };
    throw new Error(
      `no vault entry named '${name}' in project (${this.projectDir}) or global scope`
    );
  }

  list(): ScopedEntryInfo[] {
    return [
      ...this.project.list().map((e) => ({ ...e, scope: "project" as const })),
      ...this.global.list().map((e) => ({ ...e, scope: "global" as const })),
    ];
  }

  /** Union of all values in both scopes, for redaction. Project shadows global on name clash. */
  allValues(): Map<string, string> {
    const map = new Map<string, string>();
    for (const [name, value] of this.global.allValues()) map.set(`global:${name}`, value);
    for (const [name, value] of this.project.allValues()) map.set(`project:${name}`, value);
    return map;
  }
}
