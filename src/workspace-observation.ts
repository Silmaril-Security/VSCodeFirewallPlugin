import { randomUUID } from "node:crypto";
import { chmod, lstat, mkdir, open, readFile, realpath, rename, rm, stat } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

const MAX_WORKSPACES = 256;
const MAX_FILE_BYTES = 64 * 1_024;

type WorkspaceObservationV1 = {
  schemaVersion: 1;
  workspaces: Array<{ path: string; lastObservedAt: string }>;
};

export async function recordObservedWorkspace(
  cwd: unknown,
  env: Record<string, string | undefined> = process.env,
): Promise<void> {
  if (typeof cwd !== "string" || !path.isAbsolute(cwd)) return;
  let resolved: string;
  try {
    resolved = await realpath(cwd);
    if (!(await stat(resolved)).isDirectory()) return;
  } catch {
    return;
  }

  const destination = observationPath(env);
  const directory = path.dirname(destination);
  const now = new Date().toISOString();
  let current: WorkspaceObservationV1 = { schemaVersion: 1, workspaces: [] };
  try {
    const metadata = await lstat(destination);
    if (metadata.isFile() && !metadata.isSymbolicLink() && metadata.size <= MAX_FILE_BYTES) {
      const parsed: unknown = JSON.parse(await readFile(destination, "utf8"));
      if (isObservation(parsed)) current = parsed;
    }
  } catch {
    // Missing or malformed observation state starts a fresh bounded registry.
  }

  const workspaces = current.workspaces
    .filter((item) => item.path !== resolved)
    .concat({ path: resolved, lastObservedAt: now })
    .sort((left, right) => right.lastObservedAt.localeCompare(left.lastObservedAt))
    .slice(0, MAX_WORKSPACES);
  const encoded = Buffer.from(JSON.stringify({ schemaVersion: 1, workspaces }), "utf8");
  if (encoded.byteLength > MAX_FILE_BYTES) return;

  const temporary = `${destination}.${process.pid}.${randomUUID()}.tmp`;
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const directoryInfo = await lstat(directory);
    if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) return;
    await chmod(directory, 0o700);
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(encoded);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, destination);
    await chmod(destination, 0o600);
  } catch {
    await handle?.close().catch(() => undefined);
    await rm(temporary, { force: true }).catch(() => undefined);
  }
}

export function observationPath(
  env: Record<string, string | undefined> = process.env,
): string {
  const configured = env.SILMARIL_VSCODE_WORKSPACE_STATE?.trim();
  if (configured) return configured;
  return path.join(
    env.HOME?.trim() || homedir(),
    "Library",
    "Application Support",
    "Silmaril",
    "VSCode",
    "observed-workspaces.json",
  );
}

function isObservation(value: unknown): value is WorkspaceObservationV1 {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return record.schemaVersion === 1
    && Array.isArray(record.workspaces)
    && record.workspaces.every((item) => {
      if (!item || typeof item !== "object" || Array.isArray(item)) return false;
      const workspace = item as Record<string, unknown>;
      return typeof workspace.path === "string"
        && path.isAbsolute(workspace.path)
        && typeof workspace.lastObservedAt === "string";
    });
}

