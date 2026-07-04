#!/usr/bin/env node
/**
 * secrets-vault — user-facing CLI for the secrets-mcp vault.
 *
 * This is the path for entering secrets without a GUI (SSH sessions, Linux,
 * Windows) and for multi-line values pasted into the terminal. Values are
 * read from a hidden TTY prompt or from piped stdin, never from argv.
 */
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { Writable } from "node:stream";
import { Store } from "./store.js";
import { ENTRY_TYPES, type EntryType, type Scope } from "./vault.js";

interface Args {
  positional: string[];
  flags: Map<string, string | true>;
}

function parseArgs(argv: string[]): Args {
  const positional: string[] = [];
  const flags = new Map<string, string | true>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq !== -1) {
        flags.set(a.slice(2, eq), a.slice(eq + 1));
      } else if (i + 1 < argv.length && !argv[i + 1]!.startsWith("--")) {
        flags.set(a.slice(2), argv[++i]!);
      } else {
        flags.set(a.slice(2), true);
      }
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}

function usage(): never {
  console.log(`secrets-vault — encrypted credential store for secrets-mcp

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

async function readValue(name: string): Promise<string> {
  if (!process.stdin.isTTY) {
    // piped: read all of stdin (supports multi-line PEM etc.)
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
    return Buffer.concat(chunks).toString("utf8").replace(/\n$/, "");
  }
  // hidden interactive prompt
  const muted = new Writable({ write: (_c, _e, cb) => cb() });
  const rl = readline.createInterface({ input: process.stdin, output: muted, terminal: true });
  process.stderr.write(`Value for '${name}' (input hidden): `);
  const value = await new Promise<string>((resolve) => rl.question("", resolve));
  rl.close();
  process.stderr.write("\n");
  return value;
}

function scopeOf(args: Args): Scope {
  const s = args.flags.get("scope") ?? "project";
  if (s !== "global" && s !== "project") {
    console.error(`invalid --scope '${s}' (use global or project)`);
    process.exit(1);
  }
  return s;
}

function typeOf(args: Args): EntryType | undefined {
  const t = args.flags.get("type");
  if (t === undefined || t === true) return undefined;
  if (!(ENTRY_TYPES as readonly string[]).includes(t)) {
    console.error(`invalid --type '${t}'; run 'secrets-vault types' for the list`);
    process.exit(1);
  }
  return t as EntryType;
}

function str(args: Args, flag: string): string | undefined {
  const v = args.flags.get(flag);
  return typeof v === "string" ? v : undefined;
}

async function main(): Promise<void> {
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
        console.error("empty value — nothing stored");
        process.exit(1);
      }
      const info = store.vaultFor(scopeOf(args)).set(name, Buffer.from(value, "utf8"), {
        kind: "secret",
        type: typeOf(args),
        description: str(args, "description"),
      });
      console.log(`stored '${name}' (${scopeOf(args)}, ${info.type}, ${info.size} bytes)`);
      return;
    }
    case "import": {
      if (!name) usage();
      const file = str(args, "file");
      if (!file) usage();
      const abs = path.resolve(file);
      const info = store.vaultFor(scopeOf(args)).set(name, fs.readFileSync(abs), {
        kind: "file",
        type: typeOf(args),
        description: str(args, "description"),
        filename: path.basename(abs),
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
