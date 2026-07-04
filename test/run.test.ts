import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { runWithSecrets } from "../src/run.js";
import { Store } from "../src/store.js";
import { substitute } from "../src/template.js";
import { isolatedEnv } from "./helpers.js";

describe("runWithSecrets", () => {
  let env: ReturnType<typeof isolatedEnv>;
  let store: Store;

  beforeEach(async () => {
    env = isolatedEnv();
    store = await Store.open("/p");
    store.vaultFor("project").set("token", Buffer.from("super-secret-token-value"), {
      kind: "secret",
      type: "api_key",
    });
    store.vaultFor("global").set("deploy-key", Buffer.from("-----BEGIN KEY-----\nabcdef\n-----END KEY-----\n"), {
      kind: "file",
      type: "ssh_private_key",
      filename: "id_ed25519",
    });
  });
  afterEach(() => env.cleanup());

  it("injects env vars and redacts them from output", async () => {
    const result = await runWithSecrets(store, {
      command: 'echo "got: $TOKEN"',
      env: { TOKEN: "token" },
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("[REDACTED:project:token]");
    expect(result.stdout).not.toContain("super-secret-token-value");
  });

  it("redacts base64-encoded leaks", async () => {
    const result = await runWithSecrets(store, {
      command: 'printf %s "$TOKEN" | base64',
      env: { TOKEN: "token" },
    });
    expect(result.stdout).toContain("[REDACTED:project:token]");
    expect(result.stdout).not.toContain(Buffer.from("super-secret-token-value").toString("base64"));
  });

  it("materializes file entries to temp paths and cleans up", async () => {
    let capturedPath = "";
    const result = await runWithSecrets(store, {
      command: 'echo "$KEY_PATH"; test -f "$KEY_PATH" && stat -f %Lp "$KEY_PATH"',
      files: { KEY_PATH: "deploy-key" },
    });
    expect(result.exitCode).toBe(0);
    const lines = result.stdout.trim().split("\n");
    capturedPath = lines[0]!;
    expect(capturedPath).toContain(env.home); // inside the guarded vault home
    expect(capturedPath).toContain("id_ed25519");
    expect(lines[1]).toBe("600");
    expect(fs.existsSync(capturedPath)).toBe(false); // deleted after exit
  });

  it("does not leak the master key into the child environment", async () => {
    const result = await runWithSecrets(store, {
      command: 'echo "key=${SECRETS_MCP_KEY:-unset}"',
    });
    expect(result.stdout.trim()).toBe("key=unset");
  });

  it("enforces the timeout", async () => {
    const result = await runWithSecrets(store, {
      command: "sleep 10",
      timeoutMs: 300,
    });
    expect(result.timedOut).toBe(true);
  });

  it("rejects invalid env var names", async () => {
    await expect(
      runWithSecrets(store, { command: "true", env: { "BAD-NAME": "token" } })
    ).rejects.toThrow(/invalid environment variable name/);
  });
});

describe("substitute", () => {
  let env: ReturnType<typeof isolatedEnv>;

  beforeEach(() => {
    env = isolatedEnv();
  });
  afterEach(() => env.cleanup());

  it("replaces placeholders project-first", async () => {
    const store = await Store.open("/p");
    store.vaultFor("global").set("db-url", Buffer.from("postgres://global"), { kind: "secret" });
    store.vaultFor("project").set("db-url", Buffer.from("postgres://project"), { kind: "secret" });
    const { text, used } = substitute("DATABASE_URL={{vault:db-url}}", store);
    expect(text).toBe("DATABASE_URL=postgres://project");
    expect(used).toEqual(["db-url"]);
  });

  it("throws on unknown names", async () => {
    const store = await Store.open("/p");
    expect(() => substitute("X={{vault:nope}}", store)).toThrow(/no vault entry/);
  });
});
