import type { Store } from "./store.js";

const PLACEHOLDER_RE = /\{\{\s*vault:([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\s*\}\}/g;

export interface SubstitutionResult {
  text: string;
  used: string[];
}

/** Replace {{vault:NAME}} placeholders with entry values (UTF-8), project scope first. */
export function substitute(template: string, store: Store): SubstitutionResult {
  const used = new Set<string>();
  const text = template.replace(PLACEHOLDER_RE, (_m, name: string) => {
    used.add(name);
    return store.resolve(name).vault.getBytes(name).toString("utf8");
  });
  return { text, used: [...used] };
}

/** Names referenced by a template, without resolving them. */
export function referencedNames(template: string): string[] {
  const names = new Set<string>();
  for (const m of template.matchAll(PLACEHOLDER_RE)) {
    names.add(m[1]!);
  }
  return [...names];
}
