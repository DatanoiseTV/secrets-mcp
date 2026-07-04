---
name: secrets
description: Use the secrets-mcp vault whenever the task involves credentials, API keys, tokens, passwords, SSH keys, TLS certificates, private keys, .env files, connection strings, or sensitive hosts/IPs/URLs. Store, list, and USE secrets without ever seeing or asking for their values.
---

# Working with the secrets vault

This machine has an encrypted credential vault (secrets-mcp). It exists so
secret values NEVER enter the conversation: not typed by the user into chat,
not echoed by commands, not read from files. Your job is to route every
credential through the `vault_*` tools instead.

## Hard rules

1. **Never ask the user to paste a secret, key, or certificate into the chat.**
   Call `vault_set` (opens a native input dialog) or tell them to run
   `secrets-vault set <name>` / `secrets-vault import <name> --file <path>`
   in a terminal.
2. **Never try to print, cat, echo, or otherwise reveal a vault value**, and
   never ask the user what a stored value is. If a command needs it, inject it
   with `vault_run`; if an HTTP call needs it, use `vault_http`.
3. **Never read back files written by `vault_render` / `vault_write`.** They
   contain plaintext secrets and are deny-listed by a hook anyway.
4. **Don't put secrets in argv.** `vault_run` injects via environment
   variables or temp files; write commands to use `"$VAR"`, not interpolated
   values (argv is visible in `ps`; env vars are not).
5. If output unexpectedly contains `[REDACTED:...]`, that is the redaction
   layer working. Leave it redacted; never try to reconstruct the value.

## Discovering what exists

`vault_list` returns names, scope, type, and metadata — never values.
Entries live in two scopes: `project` (this repo only, resolved first) and
`global` (all projects). When storing, default to `project` scope unless the
credential is clearly machine-wide (personal GitHub token, company VPN host).

## Storing

| Material | Tool | Notes |
|---|---|---|
| API key, token, password, single-line value | `vault_set` | Native dialog, hidden input |
| IP, hostname, URL, username, email | `vault_set` with matching `type` | Visible input dialog; still stored encrypted and redacted |
| SSH key, TLS cert/key, .p12, kubeconfig, .env, any file | `vault_import` | Reads the file straight into the vault; offer `remove_source: true` for keys lying around in Downloads |
| Multi-line paste / headless session | tell user: `secrets-vault set NAME` (hidden prompt) or `pbpaste \| secrets-vault set NAME` | CLI never takes values in argv |

Always pass a `type` (`api_key`, `bearer_token`, `password`, `ssh_private_key`,
`tls_certificate`, `tls_private_key`, `pkcs12_bundle`, `connection_string`,
`webhook_secret`, `ip_address`, `hostname`, `url`, ...) and a short
`description` — it makes `vault_list` self-documenting.

## Using

**Shell command with a secret** — inject as env var, reference with `"$VAR"`:

```
vault_run {
  command: "curl -fsS -H \"Authorization: Bearer $GH\" https://api.github.com/user",
  env: { "GH": "github-token" }
}
```

**SSH key / certificate** — inject as a temp file path (0600, auto-deleted
after the command exits):

```
vault_run {
  command: "ssh -i \"$KEY\" -o IdentitiesOnly=yes deploy@{{host}} 'systemctl restart app'",
  files: { "KEY": "deploy-ssh-key" }
}
```

**API call** — placeholders resolve server-side, response comes back redacted:

```
vault_http {
  url: "https://api.example.com/v1/status",
  headers: { "Authorization": "Bearer {{vault:example-api-key}}" }
}
```

**Config / .env files** — render a template; the output file is written 0600
and guarded:

```
vault_render {
  template: "DATABASE_URL={{vault:db-url}}\nAPI_KEY={{vault:api-key}}\n",
  output_path: ".env"
}
```

**Install a key/cert at a permanent path** (e.g. `~/.ssh/id_deploy`,
nginx cert dir): `vault_write`. Prefer `vault_run` with `files` when the
material is only needed for one command.

**Removing rendered files**: files written by `vault_render` / `vault_write`
are guard-locked — `rm`, Read, and Edit on them are denied. To delete one (or
all) when no longer needed, use `vault_cleanup { path }` / `{ all: true }`;
it deletes the file and releases the guard. `{ list: true }` shows what is
currently registered. Clean up rendered files when a task is done rather than
leaving secret material on disk.

**Pre-commit / pre-post leak check**: `vault_check { text }` reports whether
any vault value (in any common encoding) appears in the text.

## Recognizing when to use this

Trigger on any of: "API key", "token", "password", "credentials", "secret",
".env", "SSH", "certificate", "private key", "p12/pfx", "connection string",
"auth", a user pasting something that looks like a credential, or a command
that would otherwise need one. If the user pastes an actual secret value into
chat, store it via their own action instead: ask them to re-enter it through
`vault_set`'s dialog or the CLI, and recommend rotating it since it has now
appeared in the conversation.

If a needed credential doesn't exist in `vault_list`, call `vault_set` /
`vault_import` to collect it from the user — don't ask for the value in chat.
