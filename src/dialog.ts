import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

/**
 * Native macOS prompts so secret values flow user -> dialog -> vault without
 * ever entering the model's context. On other platforms (or headless macOS)
 * these throw, and the tool response points the user at the CLI instead.
 */

function assertGui(): void {
  if (process.platform !== "darwin") {
    throw new Error(
      "interactive dialogs are only available on macOS; run `secrets-vault set <name>` in a terminal instead"
    );
  }
}

function appleScriptString(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** Prompt the user for a value; hidden input unless the type is non-credential data. */
export async function promptSecret(
  name: string,
  description?: string,
  hidden = true
): Promise<string> {
  assertGui();
  const label = description ? `${name}\n${description}` : name;
  const script =
    `display dialog ${appleScriptString(`Enter value for vault entry:\n\n${label}`)} ` +
    `with title "secrets-mcp" default answer ""${hidden ? " with hidden answer" : ""} ` +
    `buttons {"Cancel", "Save"} default button "Save"`;
  const { stdout } = await runOsascript(script, `user cancelled the '${name}' input dialog`);
  const marker = "text returned:";
  const idx = stdout.indexOf(marker);
  if (idx === -1) throw new Error("could not parse dialog result");
  return stdout.slice(idx + marker.length).replace(/\n$/, "");
}

/** Ask the user to confirm a destructive action. Throws if declined. */
export async function confirmAction(message: string): Promise<void> {
  assertGui();
  const script =
    `display dialog ${appleScriptString(message)} with title "secrets-mcp" ` +
    `buttons {"Cancel", "Confirm"} default button "Cancel" with icon caution`;
  await runOsascript(script, "user declined the confirmation dialog");
}

async function runOsascript(
  script: string,
  cancelMessage: string
): Promise<{ stdout: string }> {
  try {
    return await execFileP("osascript", ["-e", script], { timeout: 300_000 });
  } catch (err: unknown) {
    const e = err as { code?: number; stderr?: string };
    // osascript exits 1 with "User canceled" (-128) when Cancel is clicked
    if (e.stderr?.includes("-128")) throw new Error(cancelMessage);
    throw new Error(
      `dialog failed (${e.stderr?.trim() || "no GUI session?"}); ` +
        `run \`secrets-vault set <name>\` in a terminal instead`
    );
  }
}
