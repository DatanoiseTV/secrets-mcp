#!/usr/bin/env node
/**
 * PreToolUse guard for secrets-mcp.
 *
 * Denies the model direct access to secret material on disk:
 *  - everything under the vault home (~/.secrets-mcp): encrypted vaults,
 *    master-key fallback file, materialized temp files
 *  - files written by vault_render / vault_write (tracked in rendered.json)
 *
 * Matches Read/Grep/Glob targets exactly and scans Bash commands for the
 * guarded paths. Defense in depth, not a sandbox: the encrypted vault is
 * unreadable anyway; this keeps rendered plaintext out of the context.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

function vaultHome() {
  return process.env.SECRETS_MCP_HOME ?? path.join(os.homedir(), ".secrets-mcp");
}

function guardedPaths() {
  const home = vaultHome();
  const paths = [home];
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(home, "rendered.json"), "utf8"));
    if (Array.isArray(manifest.paths)) paths.push(...manifest.paths);
  } catch {
    // no manifest yet
  }
  return paths;
}

function normalize(p, cwd) {
  let expanded = p;
  if (expanded.startsWith("~/")) expanded = path.join(os.homedir(), expanded.slice(2));
  return path.resolve(cwd ?? process.cwd(), expanded);
}

function isGuarded(target, guarded) {
  return guarded.some((g) => target === g || target.startsWith(g + path.sep));
}

function deny(reason) {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: reason,
      },
    })
  );
  process.exit(0);
}

const input = JSON.parse(fs.readFileSync(0, "utf8"));
const tool = input.tool_name ?? "";
const args = input.tool_input ?? {};
const guarded = guardedPaths();

if (tool === "Read" || tool === "Edit" || tool === "Write" || tool === "NotebookEdit") {
  const target = args.file_path ?? args.notebook_path;
  if (target && isGuarded(normalize(target, input.cwd), guarded)) {
    deny(
      `${target} contains secret material managed by secrets-mcp. ` +
        "Use the vault_* tools (vault_run, vault_http, vault_render) instead of reading it."
    );
  }
} else if (tool === "Grep" || tool === "Glob") {
  const target = args.path;
  if (target && isGuarded(normalize(target, input.cwd), guarded)) {
    deny(`${target} is a secrets-mcp guarded location; searching it is not allowed.`);
  }
} else if (tool === "Bash") {
  const command = String(args.command ?? "");
  // cheap containment scan: any guarded path (or its ~-relative form) in the command text
  const home = os.homedir();
  for (const g of guarded) {
    const tilde = g.startsWith(home) ? "~" + g.slice(home.length) : null;
    if (command.includes(g) || (tilde && command.includes(tilde))) {
      deny(
        `This command references '${g}', which contains secret material managed by secrets-mcp. ` +
          "Use the vault_* tools instead of accessing it via shell."
      );
    }
  }
}

process.exit(0);
