import fs from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { registerRenderedPath, renderedPaths, unregisterRenderedPath } from "../src/manifest.js";
import { isolatedEnv } from "./helpers.js";

describe("rendered-file manifest", () => {
  let env: ReturnType<typeof isolatedEnv>;

  beforeEach(() => {
    env = isolatedEnv();
  });
  afterEach(() => env.cleanup());

  it("registers, lists, and unregisters paths", () => {
    const a = path.join(env.home, "out", ".env");
    const b = path.join(env.home, "out", "cert.pem");
    registerRenderedPath(a);
    registerRenderedPath(b);
    registerRenderedPath(a); // duplicate is a no-op
    expect(renderedPaths()).toEqual([a, b]);

    expect(unregisterRenderedPath(a)).toBe(true);
    expect(renderedPaths()).toEqual([b]);
    expect(unregisterRenderedPath(a)).toBe(false); // already gone
    expect(unregisterRenderedPath("/never/registered")).toBe(false);
  });

  it("survives reload from disk", () => {
    const p = path.join(env.home, "rendered-target");
    registerRenderedPath(p);
    expect(JSON.parse(fs.readFileSync(path.join(env.home, "rendered.json"), "utf8")).paths).toEqual([p]);
  });
});
