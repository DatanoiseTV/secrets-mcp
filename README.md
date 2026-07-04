# secrets-mcp

An encrypted credential vault for Claude Code (and any MCP client): store and
*use* API keys, passwords, tokens, SSH keys, TLS certificates, and other
sensitive material without the values ever entering the model's context.

The model can list what exists, collect new credentials from the user, run
commands with credentials injected, call APIs with stored tokens, and render
config files — but it never sees a value. Ships as a Claude Code plugin
bundling the MCP server, a guard hook, and a skill.

## How values stay out of the model

- **Input never crosses the chat.** `vault_set` opens a native dialog
  (hidden input on macOS) where the user types the value; `vault_import`
  reads a file straight from disk into the vault. Headless/Linux/Windows:
  the `secrets-vault` CLI reads from a hidden TTY prompt or piped stdin —
  never argv.
- **Output is redacted.** `vault_run` and `vault_http` scrub every stored
  value from captured output before it is returned — raw, base64, base64url,
  hex, URL-encoded, and JSON-escaped forms, plus each individual line of
  multi-line values (so `grep`/`head` on a PEM file comes back redacted).
- **Disk is guarded.** A PreToolUse hook denies the model Read/Edit/Grep/Bash
  access to the vault directory and to any file produced by `vault_render`
  or `vault_write`.
- **Storage is encrypted.** AES-256-GCM vault files; the master key lives in
  the platform credential store — macOS Keychain, Linux libsecret
  (`secret-tool`), Windows DPAPI — with a 0600 key file as last-resort
  fallback. Key material moves over stdin/stdout, never argv.

## Threat model — read this

This protects against **accidental exposure**: secrets pasted into chat,
echoed by commands, logged, committed, or read out of config files into the
conversation. It is **not** a sandbox against an adversarial model. A model
that deliberately transforms a secret before printing it (e.g.
`cut -c1-4`, character arithmetic, XOR) defeats exact-match redaction — the
redaction layer catches common encodings and line-wise extraction, not
arbitrary computation. If that is your threat, the mitigation is Claude
Code's permission prompts on `vault_run` commands, not this tool.

Materialized files (`vault_render` / `vault_write` outputs, `files:` temp
paths) are plaintext on disk while they exist; temp files are 0600, created
inside the guarded directory, and deleted when the command exits.

## Entry model

| | |
|---|---|
| **Scope** | `project` (per project directory, resolved first) or `global` (all projects). Project vaults are stored centrally under `~/.secrets-mcp/projects/`, keyed by project path — nothing lives in the repo, so nothing can be committed. |
| **Kind** | `secret` (text) or `file` (arbitrary bytes: PEM, PKCS#12, kubeconfig, ...) |
| **Type** | `password`, `api_key`, `bearer_token`, `oauth_token`, `ssh_private_key`, `ssh_public_key`, `tls_certificate`, `tls_private_key`, `pkcs12_bundle`, `gpg_key`, `connection_string`, `webhook_secret`, `totp_seed`, `ip_address`, `hostname`, `url`, `username`, `email`, `generic` |

Non-credential types (`ip_address`, `hostname`, `url`, `username`, `email`)
get a visible input dialog but are stored, redacted, and injected exactly
like secrets — useful for infrastructure details that should not appear in
transcripts.

## MCP tools

| Tool | Purpose |
|---|---|
| `vault_list` | Names and metadata only — never values |
| `vault_set` | Store a text value via native user dialog |
| `vault_import` | Import a file (keys, certs, .env) from disk; optional source shredding |
| `vault_delete` | Delete after native user confirmation |
| `vault_run` | Run a shell command; entries injected as env vars (`env`) or auto-cleaned 0600 temp files (`files`); output redacted |
| `vault_http` | HTTP request with `{{vault:NAME}}` placeholders in URL/headers/body; response redacted |
| `vault_render` | Render a template (`{{vault:NAME}}`) to a 0600 file; output path guarded |
| `vault_write` | Materialize one entry to a permanent path (installing certs/keys); path guarded |
| `vault_check` | Leak check: report whether text contains any stored value in any common encoding |

Example — the model deploys over SSH without ever holding the key:

```json
vault_run {
  "command": "ssh -i \"$KEY\" -o IdentitiesOnly=yes deploy@prod 'systemctl restart app'",
  "files": { "KEY": "deploy-ssh-key" }
}
```

## CLI

For terminals, SSH sessions, and multi-line values:

```console
$ secrets-vault set github-token --type api_key --scope global
Value for 'github-token' (input hidden): ...
$ secrets-vault import deploy-key --file ~/.ssh/id_deploy --type ssh_private_key
$ pbpaste | secrets-vault set staging-db --type connection_string
$ secrets-vault list
$ secrets-vault rm old-token --scope project
```

## Install

```console
$ npm install && npm run build
```

As a Claude Code plugin (MCP server + guard hook + skill):

```console
$ claude --plugin-dir /path/to/secrets-mcp        # try it
$ claude plugin install /path/to/secrets-mcp --scope user
```

Or just the MCP server, without the plugin:

```console
$ claude mcp add --scope user secrets -- node /path/to/secrets-mcp/dist/index.js
```

## Environment

| Variable | Effect |
|---|---|
| `SECRETS_MCP_HOME` | Vault directory (default `~/.secrets-mcp`) |
| `SECRETS_MCP_KEY` | Master key override, 64 hex chars — tests/headless use |
| `SECRETS_MCP_PROJECT` | Project directory override (default: server cwd) |

## Development

```console
$ npm test          # vitest: crypto round-trips, scoping, redaction, injection, cleanup
```

Tests run against an isolated `SECRETS_MCP_HOME` with an env master key; they
never touch the real keychain or vault.
