import fs from "node:fs";
import path from "node:path";
import { manifestFile, vaultHome } from "./paths.js";

/**
 * Tracks files that were written with secret material in them (vault_render /
 * vault_write outputs). The guard hook reads this manifest and denies the
 * model Read/Bash access to the listed paths.
 */

interface Manifest {
  paths: string[];
}

function load(): Manifest {
  try {
    return JSON.parse(fs.readFileSync(manifestFile(), "utf8")) as Manifest;
  } catch {
    return { paths: [] };
  }
}

export function registerRenderedPath(p: string): void {
  const abs = path.resolve(p);
  const manifest = load();
  if (!manifest.paths.includes(abs)) {
    manifest.paths.push(abs);
    fs.mkdirSync(vaultHome(), { recursive: true, mode: 0o700 });
    fs.writeFileSync(manifestFile(), JSON.stringify(manifest, null, 2) + "\n", {
      mode: 0o600,
    });
  }
}

export function renderedPaths(): string[] {
  return load().paths;
}
