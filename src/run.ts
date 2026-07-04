import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { tmpDir } from "./paths.js";
import { redact } from "./redact.js";
import type { Store } from "./store.js";

const OUTPUT_CAP = 64 * 1024; // per stream, post-redaction

export interface RunResult {
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  timedOut: boolean;
}

export interface RunOptions {
  command: string;
  /** env var name -> vault entry name; value injected as the variable's value */
  env?: Record<string, string>;
  /**
   * env var name -> vault entry name; entry is materialized to a 0600 temp
   * file inside the guarded vault home and the PATH to it is injected as the
   * variable's value. The file is deleted when the command exits.
   */
  files?: Record<string, string>;
  cwd?: string;
  timeoutMs?: number;
}

export async function runWithSecrets(store: Store, opts: RunOptions): Promise<RunResult> {
  const childEnv: NodeJS.ProcessEnv = { ...process.env };
  delete childEnv.SECRETS_MCP_KEY;

  for (const [envName, entryName] of Object.entries(opts.env ?? {})) {
    assertEnvName(envName);
    childEnv[envName] = store.resolve(entryName).vault.getBytes(entryName).toString("utf8");
  }

  const scratch = fs.mkdtempSync(path.join(ensureTmpDir(), "run-"));
  try {
    for (const [envName, entryName] of Object.entries(opts.files ?? {})) {
      assertEnvName(envName);
      const { vault } = store.resolve(entryName);
      const entry = vault.getEntry(entryName);
      const base = entry.filename ?? entryName;
      const file = path.join(scratch, `${crypto.randomBytes(4).toString("hex")}-${path.basename(base)}`);
      fs.writeFileSync(file, vault.getBytes(entryName), { mode: 0o600 });
      childEnv[envName] = file;
    }

    const result = await execute(opts, childEnv);
    const secrets = store.allValues();
    const stdout = cap(redact(result.stdout, secrets));
    const stderr = cap(redact(result.stderr, secrets));
    return {
      ...result,
      stdout: stdout.text,
      stderr: stderr.text,
      truncated: stdout.truncated || stderr.truncated,
    };
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

function ensureTmpDir(): string {
  const dir = tmpDir();
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

function assertEnvName(name: string): void {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
    throw new Error(`invalid environment variable name '${name}'`);
  }
}

function cap(text: string): { text: string; truncated: boolean } {
  if (text.length <= OUTPUT_CAP) return { text, truncated: false };
  return {
    text: text.slice(0, OUTPUT_CAP) + "\n[output truncated]",
    truncated: true,
  };
}

function execute(
  opts: RunOptions,
  env: NodeJS.ProcessEnv
): Promise<Omit<RunResult, "truncated">> {
  return new Promise((resolve, reject) => {
    const child = spawn("/bin/sh", ["-c", opts.command], {
      cwd: opts.cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const timeoutMs = opts.timeoutMs ?? 120_000;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 5_000).unref();
    }, timeoutMs);

    const out: Buffer[] = [];
    const err: Buffer[] = [];
    let outLen = 0;
    let errLen = 0;
    const RAW_CAP = 4 * 1024 * 1024;
    child.stdout.on("data", (d: Buffer) => {
      if (outLen < RAW_CAP) { out.push(d); outLen += d.length; }
    });
    child.stderr.on("data", (d: Buffer) => {
      if (errLen < RAW_CAP) { err.push(d); errLen += d.length; }
    });
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({
        exitCode: code,
        signal,
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
        timedOut,
      });
    });
  });
}
