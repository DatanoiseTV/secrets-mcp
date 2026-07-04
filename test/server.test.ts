import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildServer } from "../src/server.js";
import { Store } from "../src/store.js";
import { isolatedEnv } from "./helpers.js";

describe("server error paths", () => {
  let env: ReturnType<typeof isolatedEnv>;
  let client: Client;

  beforeEach(async () => {
    env = isolatedEnv();
    const store = await Store.open("/p");
    store.vaultFor("project").set("ml", Buffer.from("line1-secret\nline2-secret"), { kind: "secret" });
    store.vaultFor("project").set("tok", Buffer.from("tok-leakable-value"), { kind: "secret" });
    const server = buildServer(store, "0.0.0-test");
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    client = new Client({ name: "test", version: "0.0.0" });
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  });
  afterEach(async () => {
    await client.close();
    env.cleanup();
  });

  async function callText(name: string, args: Record<string, unknown>) {
    const r = (await client.callTool({ name, arguments: args })) as {
      isError?: boolean;
      content: Array<{ text: string }>;
    };
    return { isError: r.isError ?? false, text: r.content[0]!.text };
  }

  it("redacts secrets from vault_http header-validation errors", async () => {
    // newline in a resolved header value makes undici throw an error that
    // quotes the raw value verbatim
    const r = await callText("vault_http", {
      url: "http://127.0.0.1:1/x",
      headers: { "X-Test": "v={{vault:ml}}" },
    });
    expect(r.isError).toBe(true);
    expect(r.text).not.toContain("line1-secret");
    expect(r.text).not.toContain("line2-secret");
    expect(r.text).toContain("[REDACTED:");
  });

  it("redacts secrets from error cause chains", async () => {
    // unreachable host: undici throws TypeError("fetch failed", {cause});
    // url contains a resolved secret which must not surface via message or cause
    const r = await callText("vault_http", {
      url: "http://127.0.0.1:1/{{vault:tok}}",
      timeout_ms: 2000,
    });
    expect(r.isError).toBe(true);
    expect(r.text).not.toContain("tok-leakable-value");
  });

  it("keeps unknown-entry errors clean and value-free", async () => {
    const r = await callText("vault_run", { command: "true", env: { X: "nope" } });
    expect(r.isError).toBe(true);
    expect(r.text).toContain("no vault entry named 'nope'");
    expect(r.text).not.toContain("tok-leakable-value");
  });
});
