import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Store } from "../src/store.js";
import { isolatedEnv } from "./helpers.js";

describe("Store", () => {
  let env: ReturnType<typeof isolatedEnv>;

  beforeEach(() => {
    env = isolatedEnv();
  });
  afterEach(() => env.cleanup());

  it("stores and retrieves entries per scope", async () => {
    const store = await Store.open("/some/project");
    store.vaultFor("global").set("token", Buffer.from("g-value"), { kind: "secret", type: "api_key" });
    store.vaultFor("project").set("token", Buffer.from("p-value"), { kind: "secret" });

    // project shadows global on resolve
    const resolved = store.resolve("token");
    expect(resolved.scope).toBe("project");
    expect(resolved.vault.getBytes("token").toString()).toBe("p-value");

    const entries = store.list();
    expect(entries).toHaveLength(2);
    expect(entries.find((e) => e.scope === "global")!.type).toBe("api_key");
    // values never appear in listings
    expect(JSON.stringify(entries)).not.toContain("g-value");
    expect(JSON.stringify(entries)).not.toContain("p-value");
  });

  it("isolates project vaults by directory", async () => {
    const a = await Store.open("/project/a");
    a.vaultFor("project").set("db", Buffer.from("secret-a"), { kind: "secret" });

    const b = await Store.open("/project/b");
    expect(b.project.has("db")).toBe(false);
    expect(() => b.resolve("db")).toThrow(/no vault entry/);

    // but global entries are shared
    a.vaultFor("global").set("shared", Buffer.from("everywhere"), { kind: "secret" });
    const b2 = await Store.open("/project/b");
    expect(b2.resolve("shared").scope).toBe("global");
  });

  it("persists encrypted and reloads", async () => {
    const store = await Store.open("/p");
    store.vaultFor("global").set("key", Buffer.from("hello-world-secret"), {
      kind: "secret",
      description: "test key",
    });

    const raw = fs.readFileSync(path.join(env.home, "vault.enc"), "utf8");
    expect(raw).not.toContain("hello-world-secret");
    expect(raw).not.toContain(Buffer.from("hello-world-secret").toString("base64"));

    const reloaded = await Store.open("/p");
    expect(reloaded.global.getBytes("key").toString()).toBe("hello-world-secret");
    expect(reloaded.global.getEntry("key").description).toBe("test key");
  });

  it("fails closed on a wrong master key", async () => {
    const store = await Store.open("/p");
    store.vaultFor("global").set("key", Buffer.from("value"), { kind: "secret" });
    process.env.SECRETS_MCP_KEY = crypto.randomBytes(32).toString("hex");
    await expect(Store.open("/p")).rejects.toThrow();
  });

  it("stores binary file entries intact", async () => {
    const store = await Store.open("/p");
    const blob = crypto.randomBytes(1024); // e.g. a DER cert or .p12
    store.vaultFor("project").set("cert", blob, { kind: "file", type: "pkcs12_bundle", filename: "client.p12" });
    const back = (await Store.open("/p")).project;
    expect(back.getBytes("cert").equals(blob)).toBe(true);
    expect(back.getEntry("cert").filename).toBe("client.p12");
  });

  it("rejects invalid names and empty values", async () => {
    const store = await Store.open("/p");
    expect(() => store.global.set("bad name!", Buffer.from("x"), { kind: "secret" })).toThrow(/invalid entry name/);
    expect(() => store.global.set("ok", Buffer.alloc(0), { kind: "secret" })).toThrow(/empty value/);
  });
});
