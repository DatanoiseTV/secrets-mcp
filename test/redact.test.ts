import { describe, expect, it } from "vitest";
import { redact, variantsOf } from "../src/redact.js";

describe("redact", () => {
  const secrets = new Map([["API_KEY", "sk-live-abc123XYZ"]]);

  it("redacts the raw value", () => {
    expect(redact("token is sk-live-abc123XYZ ok", secrets)).toBe("token is [REDACTED:API_KEY] ok");
  });

  it("redacts base64, base64url, hex, url-encoded and JSON-escaped forms", () => {
    const value = "p@ss/w+rd=1&x";
    const s = new Map([["PW", value]]);
    const buf = Buffer.from(value);
    for (const encoded of [
      buf.toString("base64"),
      buf.toString("base64url"),
      buf.toString("hex"),
      buf.toString("hex").toUpperCase(),
      encodeURIComponent(value),
      JSON.stringify(value).slice(1, -1),
    ]) {
      expect(redact(`>>${encoded}<<`, s)).toContain("[REDACTED:PW]");
    }
  });

  it("redacts multi-line values such as PEM keys", () => {
    const pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----\n";
    const s = new Map([["SSH", pem]]);
    expect(redact(`dump:\n${pem}done`, s)).toBe("dump:\n[REDACTED:SSH]done");
    // trimmed variant catches the value without its trailing newline
    expect(redact(`dump:${pem.trim()}`, s)).toBe("dump:[REDACTED:SSH]");
  });

  it("redacts individual lines of multi-line values (head/grep/sed extraction)", () => {
    const pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQ\nqhkiG9w0BAQEFAASCBKcwggSjAg\n-----END PRIVATE KEY-----\n";
    const s = new Map([["KEY", pem]]);
    // a single body line, as `sed -n 2p key.pem` would print it
    expect(redact("line: MIIEvQIBADANBgkqhkiG9w0BAQ", s)).toBe("line: [REDACTED:KEY]");
    // base64 of a body line
    const b64 = Buffer.from("MIIEvQIBADANBgkqhkiG9w0BAQ").toString("base64");
    expect(redact(b64, s)).toBe("[REDACTED:KEY]");
    // PEM armor lines are structural, not secret — never redacted
    expect(redact("-----BEGIN PRIVATE KEY-----", s)).toBe("-----BEGIN PRIVATE KEY-----");
  });

  it("skips values too short to redact safely", () => {
    expect(variantsOf("ab")).toEqual([]);
    expect(redact("ab is fine", new Map([["X", "ab"]]))).toBe("ab is fine");
  });

  it("handles multiple secrets with overlapping content", () => {
    const s = new Map([
      ["LONG", "secret-value-long"],
      ["SHORT", "secret-value"],
    ]);
    const out = redact("secret-value-long and secret-value", s);
    expect(out).toBe("[REDACTED:LONG] and [REDACTED:SHORT]");
  });
});
