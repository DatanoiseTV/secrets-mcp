import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import fs from "node:fs";
import path from "node:path";
import { z } from "zod";
import { confirmAction, promptSecret } from "./dialog.js";
import { httpWithSecrets } from "./http.js";
import { registerRenderedPath, renderedPaths, unregisterRenderedPath } from "./manifest.js";
import { redact } from "./redact.js";
import { runWithSecrets } from "./run.js";
import type { Store } from "./store.js";
import { referencedNames, substitute } from "./template.js";
import { ENTRY_TYPES, NON_CREDENTIAL_TYPES, type EntryType, type Scope } from "./vault.js";

const scopeSchema = z
  .enum(["global", "project"])
  .describe("Where the entry lives. 'project' entries are only visible in this project.");

const typeSchema = z
  .enum(ENTRY_TYPES)
  .optional()
  .describe("What the credential is, e.g. api_key, bearer_token, ssh_private_key, tls_certificate, ip_address, url.");

type ToolResult = {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
};

function ok(payload: unknown): ToolResult {
  return {
    content: [{ type: "text", text: typeof payload === "string" ? payload : JSON.stringify(payload, null, 2) }],
  };
}

function fail(err: unknown): ToolResult {
  const message = err instanceof Error ? err.message : String(err);
  return { content: [{ type: "text", text: `Error: ${message}` }], isError: true };
}

export function buildServer(store: Store, version: string): McpServer {
  const server = new McpServer({ name: "secrets-mcp", version });

  server.registerTool(
    "vault_list",
    {
      description:
        "List vault entries (names and metadata only — never values). Shows scope (global/project), " +
        "type, kind, size, sha256, and description. Use this to discover what credentials are available.",
      inputSchema: {},
    },
    async () => {
      try {
        return ok({
          project: store.projectDir,
          entries: store.list(),
        });
      } catch (e) {
        return fail(e);
      }
    }
  );

  server.registerTool(
    "vault_set",
    {
      description:
        "Store or update a text entry (API key, password, token, IP, hostname, URL...). Opens a native " +
        "dialog where the USER types the value — the value never passes through the model. Never ask the " +
        "user to paste a secret into the chat; call this instead. For multi-line material (SSH keys, " +
        "certificates) use vault_import.",
      inputSchema: {
        name: z.string().describe("Entry name, e.g. GITHUB_TOKEN or prod-db-password"),
        scope: scopeSchema.default("project"),
        type: typeSchema,
        description: z.string().optional().describe("Human-readable note shown in the dialog and in vault_list"),
      },
    },
    async ({ name, scope, type, description }) => {
      try {
        const hidden = !NON_CREDENTIAL_TYPES.has((type ?? "generic") as EntryType);
        const value = await promptSecret(name, description, hidden);
        if (value.length === 0) throw new Error("empty value — nothing stored");
        const info = store
          .vaultFor(scope as Scope)
          .set(name, Buffer.from(value, "utf8"), { kind: "secret", type, description });
        return ok({ stored: name, scope, type: info.type, size: info.size, sha256: info.sha256 });
      } catch (e) {
        return fail(e);
      }
    }
  );

  server.registerTool(
    "vault_import",
    {
      description:
        "Import a file into the vault: SSH private keys, TLS certificates, PKCS#12 bundles, .env files, " +
        "kubeconfigs — any text or binary file. The content is read directly from disk into the encrypted " +
        "vault without passing through the model. Optionally shreds the source file afterwards.",
      inputSchema: {
        name: z.string().describe("Entry name, e.g. deploy-ssh-key"),
        path: z.string().describe("Absolute path of the file to import"),
        scope: scopeSchema.default("project"),
        type: typeSchema,
        description: z.string().optional(),
        remove_source: z
          .boolean()
          .default(false)
          .describe("Delete the source file after importing (asks the user for confirmation)"),
      },
    },
    async ({ name, path: srcPath, scope, type, description, remove_source }) => {
      try {
        const abs = path.resolve(srcPath);
        const data = fs.readFileSync(abs);
        const info = store.vaultFor(scope as Scope).set(name, data, {
          kind: "file",
          type,
          description,
          filename: path.basename(abs),
        });
        let removed = false;
        if (remove_source) {
          await confirmAction(`secrets-mcp imported '${name}'.\n\nDelete the source file?\n${abs}`);
          fs.rmSync(abs);
          removed = true;
        }
        return ok({
          imported: name,
          scope,
          type: info.type,
          size: info.size,
          sha256: info.sha256,
          sourceRemoved: removed,
        });
      } catch (e) {
        return fail(e);
      }
    }
  );

  server.registerTool(
    "vault_delete",
    {
      description:
        "Delete a vault entry. Asks the user for confirmation via a native dialog before deleting.",
      inputSchema: {
        name: z.string(),
        scope: scopeSchema,
      },
    },
    async ({ name, scope }) => {
      try {
        const vault = store.vaultFor(scope as Scope);
        if (!vault.has(name)) throw new Error(`no ${scope} vault entry named '${name}'`);
        await confirmAction(`Delete ${scope} vault entry '${name}'?\n\nThis cannot be undone.`);
        vault.delete(name);
        return ok({ deleted: name, scope });
      } catch (e) {
        return fail(e);
      }
    }
  );

  server.registerTool(
    "vault_run",
    {
      description:
        "Run a shell command with vault entries injected — the model never sees the values. " +
        "'env' maps environment variable names to entry names (value injected directly). " +
        "'files' maps environment variable names to entry names whose content is written to a " +
        "temporary 0600 file; the variable receives the file PATH (use for SSH keys, certs: " +
        "e.g. ssh -i \"$DEPLOY_KEY\" or curl --cert \"$CLIENT_CERT\"). Temp files are deleted when " +
        "the command exits. stdout/stderr are redacted against all vault values before being returned. " +
        "Entry names resolve project scope first, then global.",
      inputSchema: {
        command: z.string().describe("Shell command, run via /bin/sh -c"),
        env: z
          .record(z.string())
          .optional()
          .describe('{"ENV_VAR": "entry-name"} — inject entry value as environment variable'),
        files: z
          .record(z.string())
          .optional()
          .describe('{"ENV_VAR": "entry-name"} — materialize entry to a temp file, inject its path'),
        cwd: z.string().optional(),
        timeout_ms: z.number().int().positive().max(600_000).optional(),
      },
    },
    async ({ command, env, files, cwd, timeout_ms }) => {
      try {
        const result = await runWithSecrets(store, {
          command,
          env,
          files,
          cwd,
          timeoutMs: timeout_ms,
        });
        return ok(result);
      } catch (e) {
        return fail(e);
      }
    }
  );

  server.registerTool(
    "vault_http",
    {
      description:
        "Make an HTTP request using vault entries, e.g. call an API with a stored token. " +
        "Use {{vault:NAME}} placeholders in the url, headers, or body — they are resolved server-side " +
        "and the response is redacted before the model sees it. " +
        'Example: headers {"Authorization": "Bearer {{vault:GITHUB_TOKEN}}"}.',
      inputSchema: {
        url: z.string(),
        method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]).default("GET"),
        headers: z.record(z.string()).optional(),
        body: z.string().optional(),
        timeout_ms: z.number().int().positive().max(300_000).optional(),
      },
    },
    async ({ url, method, headers, body, timeout_ms }) => {
      try {
        const result = await httpWithSecrets(store, {
          url,
          method,
          headers,
          body,
          timeoutMs: timeout_ms,
        });
        return ok(result);
      } catch (e) {
        return fail(e);
      }
    }
  );

  server.registerTool(
    "vault_render",
    {
      description:
        "Render a template to a file, replacing {{vault:NAME}} placeholders with entry values — for " +
        ".env files, config files, kubeconfigs. The output file is written with mode 0600 and " +
        "registered so the guard hook denies the model access to it. Provide either template " +
        "(inline text) or template_path (file to read).",
      inputSchema: {
        template: z.string().optional().describe("Inline template text"),
        template_path: z.string().optional().describe("Path to a template file"),
        output_path: z.string().describe("Where to write the rendered file"),
      },
    },
    async ({ template, template_path, output_path }) => {
      try {
        if ((template === undefined) === (template_path === undefined)) {
          throw new Error("provide exactly one of template or template_path");
        }
        const source = template ?? fs.readFileSync(path.resolve(template_path!), "utf8");
        const names = referencedNames(source);
        if (names.length === 0) {
          throw new Error("template contains no {{vault:NAME}} placeholders");
        }
        const { text, used } = substitute(source, store);
        const outAbs = path.resolve(output_path);
        fs.mkdirSync(path.dirname(outAbs), { recursive: true });
        fs.writeFileSync(outAbs, text, { mode: 0o600 });
        registerRenderedPath(outAbs);
        return ok({
          written: outAbs,
          mode: "0600",
          secretsUsed: used,
          note: "file contains secret material; it is registered with the guard hook and must not be read back",
        });
      } catch (e) {
        return fail(e);
      }
    }
  );

  server.registerTool(
    "vault_write",
    {
      description:
        "Write one vault entry verbatim to a file (mode 0600) — for long-lived materialization such as " +
        "installing a certificate or an SSH key at a known path. The path is registered with the guard " +
        "hook. Prefer vault_run with 'files' for one-shot use; it cleans up automatically.",
      inputSchema: {
        name: z.string(),
        output_path: z.string(),
      },
    },
    async ({ name, output_path }) => {
      try {
        const { vault, scope } = store.resolve(name);
        const outAbs = path.resolve(output_path);
        fs.mkdirSync(path.dirname(outAbs), { recursive: true });
        fs.writeFileSync(outAbs, vault.getBytes(name), { mode: 0o600 });
        registerRenderedPath(outAbs);
        return ok({
          written: outAbs,
          from: name,
          scope,
          mode: "0600",
          note: "file contains secret material; it is registered with the guard hook and must not be read back",
        });
      } catch (e) {
        return fail(e);
      }
    }
  );

  server.registerTool(
    "vault_cleanup",
    {
      description:
        "Delete files previously produced by vault_render / vault_write and release them from the " +
        "guard hook. Only guard-registered paths can be targeted — this cannot delete arbitrary files. " +
        "Pass a specific path, or all=true to remove every rendered file. Rendered files are derived " +
        "output and can always be regenerated from the vault.",
      inputSchema: {
        path: z.string().optional().describe("One rendered file to delete and unregister"),
        all: z.boolean().default(false).describe("Delete and unregister every rendered file"),
        list: z.boolean().default(false).describe("Only list currently registered rendered paths"),
      },
    },
    async ({ path: target, all, list }) => {
      try {
        if (list) return ok({ registered: renderedPaths() });
        if ((target === undefined) === !all) {
          throw new Error("provide exactly one of path or all=true (or list=true)");
        }
        const targets = all ? renderedPaths() : [path.resolve(target!)];
        const removed: string[] = [];
        const alreadyGone: string[] = [];
        for (const p of targets) {
          if (!unregisterRenderedPath(p)) {
            throw new Error(`${p} is not a registered rendered file`);
          }
          if (fs.existsSync(p)) {
            fs.rmSync(p);
            removed.push(p);
          } else {
            alreadyGone.push(p);
          }
        }
        return ok({ removed, alreadyGone });
      } catch (e) {
        return fail(e);
      }
    }
  );

  server.registerTool(
    "vault_check",
    {
      description:
        "Check text for accidentally embedded vault values (e.g. before committing a file or posting " +
        "output). Returns the redacted text and which entries were found.",
      inputSchema: {
        text: z.string(),
      },
    },
    async ({ text }) => {
      try {
        const secrets = store.allValues();
        const redacted = redact(text, secrets);
        const found = [...secrets.keys()].filter((name) => redacted.includes(`[REDACTED:${name}]`));
        return ok({ clean: found.length === 0, found, redacted: found.length > 0 ? redacted : undefined });
      } catch (e) {
        return fail(e);
      }
    }
  );

  return server;
}
