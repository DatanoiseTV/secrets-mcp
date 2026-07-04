/**
 * Scrubs secret values out of text before it is returned to the model.
 *
 * For each secret we redact the raw value plus common encodings a command
 * might apply to it: base64, base64url, hex (both cases), URL-encoding, and
 * JSON string escaping. This catches accidental exposure (`env`, echoed
 * config, verbose logs). It is NOT proof against a deliberately obfuscating
 * command — see the threat model in the README.
 */

const MIN_LEN = 4; // redacting shorter values would shred unrelated output
const MIN_LINE_LEN = 8; // per-line redaction needs more entropy to be safe
const MAX_VALUE_LEN = 256 * 1024;

// PEM armor lines are structural, not secret; redacting them would mangle
// unrelated certificates the model legitimately works with
const PEM_ARMOR_RE = /^-----(BEGIN|END) [A-Z0-9 ]+-----$/;

function encodingsOf(value: string): string[] {
  const buf = Buffer.from(value, "utf8");
  return [
    value,
    buf.toString("base64"),
    buf.toString("base64url"),
    buf.toString("hex"),
    buf.toString("hex").toUpperCase(),
    encodeURIComponent(value),
    JSON.stringify(value).slice(1, -1),
  ];
}

export function variantsOf(value: string): string[] {
  if (value.length < MIN_LEN || value.length > MAX_VALUE_LEN) return [];
  const out = new Set<string>(encodingsOf(value));
  // trimmed variant catches values stored with a trailing newline (files)
  const trimmed = value.trim();
  if (trimmed.length >= MIN_LEN && trimmed !== value) {
    for (const v of encodingsOf(trimmed)) out.add(v);
  }
  // individual lines of multi-line values (PEM bodies, multi-line configs):
  // catches line-wise extraction via head/grep/sed that whole-value matching misses
  if (value.includes("\n")) {
    for (const line of value.split("\n")) {
      const t = line.trim();
      if (t.length >= MIN_LINE_LEN && !PEM_ARMOR_RE.test(t)) {
        for (const v of encodingsOf(t)) out.add(v);
      }
    }
  }
  return [...out].filter((v) => v.length >= MIN_LEN);
}

export function redact(text: string, secrets: Map<string, string>): string {
  let result = text;
  // longest variants first so partial overlaps don't leave fragments behind
  const pairs: Array<[string, string]> = [];
  for (const [name, value] of secrets) {
    for (const variant of variantsOf(value)) {
      pairs.push([variant, name]);
    }
  }
  pairs.sort((a, b) => b[0].length - a[0].length);
  for (const [variant, name] of pairs) {
    result = result.split(variant).join(`[REDACTED:${name}]`);
  }
  return result;
}
