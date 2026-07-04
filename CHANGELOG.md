# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project uses [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-07-04

### Added

- `vault_cleanup` tool: delete files produced by `vault_render` /
  `vault_write` and release them from the guard hook. Previously
  guard-registered files had no in-band removal path — the guard denied
  `rm` along with reads. Only manifest-registered paths can be targeted.

## [0.1.0] - 2026-07-04

### Added

- MCP server (stdio) with tools: `vault_list`, `vault_set`, `vault_import`,
  `vault_delete`, `vault_run`, `vault_http`, `vault_render`, `vault_write`,
  `vault_check`. No tool ever returns a stored value.
- AES-256-GCM encrypted vault files; master key in macOS Keychain, Linux
  libsecret, or Windows DPAPI, with a 0600 key-file fallback.
- Global and per-project scopes; project vaults stored centrally under
  `~/.secrets-mcp/projects/`, resolved project-first.
- Typed entries (`api_key`, `bearer_token`, `password`, `ssh_private_key`,
  `tls_certificate`, `pkcs12_bundle`, `ip_address`, `hostname`, `url`, ...)
  with text and binary payloads.
- Output redaction covering raw, base64, base64url, hex, URL-encoded, and
  JSON-escaped encodings, plus individual lines of multi-line values.
- Secret injection into subprocesses as environment variables or auto-cleaned
  0600 temp files; HTTP requests with server-side `{{vault:NAME}}` placeholder
  resolution and redacted responses.
- `secrets-vault` CLI: `set` (hidden prompt / piped stdin), `import`, `list`,
  `rm`, `types`.
- Claude Code plugin packaging: MCP server registration, PreToolUse guard
  hook denying model access to vault and rendered files, and a `secrets`
  skill teaching credential workflows.
