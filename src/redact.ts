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
const MAX_VALUE_LEN = 256 * 1024;

export function variantsOf(value: string): string[] {
  if (value.length < MIN_LEN || value.length > MAX_VALUE_LEN) return [];
  const buf = Buffer.from(value, "utf8");
  const out = new Set<string>([
    value,
    buf.toString("base64"),
    buf.toString("base64url"),
    buf.toString("hex"),
    buf.toString("hex").toUpperCase(),
    encodeURIComponent(value),
    JSON.stringify(value).slice(1, -1),
  ]);
  // trimmed variant catches values stored with a trailing newline (files)
  const trimmed = value.trim();
  if (trimmed.length >= MIN_LEN && trimmed !== value) {
    for (const v of variantsOf(trimmed)) out.add(v);
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
