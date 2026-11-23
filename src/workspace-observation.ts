import { randomUUID } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  rmdir,
  stat,
  unlink,
} from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const MAX_WORKSPACES = 256;
const MAX_FILE_BYTES = 64 * 1_024;
const LOCK_WAIT_MS = 1_000;
const LOCK_POLL_MS = 10;
const STALE_LOCK_MS = 30_000;
const LOCK_OWNER_PATTERN =
  /^owner-([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/u;

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
  try {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const directoryInfo = await lstat(directory);
    if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) return;
    await chmod(directory, 0o700);
  } catch {
    return;
  }

  const releaseLock = await acquireRegistryLock(destination);
  if (!releaseLock) return;
  try {
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
  } finally {
    await releaseLock();
  }
}

async function acquireRegistryLock(destination: string): Promise<(() => Promise<void>) | undefined> {
  const lockPath = `${destination}.lock`;
  const deadline = Date.now() + LOCK_WAIT_MS;
  const ownerToken = randomUUID();
  const ownerName = `owner-${ownerToken}`;
  const claimPath = `${lockPath}.${ownerToken}.claim`;
  let claimCreated = false;
  let ownerCreated = false;
  let published = false;
  let handle: Awaited<ReturnType<typeof open>> | undefined;

  try {
    try {
      await mkdir(claimPath, { mode: 0o700 });
      claimCreated = true;
      handle = await open(path.join(claimPath, ownerName), "wx", 0o600);
      ownerCreated = true;
      await handle.writeFile(ownerToken, "utf8");
      await handle.sync();
      await handle.close();
      handle = undefined;
    } catch {
      await handle?.close().catch(() => undefined);
      handle = undefined;
      return undefined;
    }

    while (Date.now() <= deadline) {
      let metadata: Awaited<ReturnType<typeof lstat>>;
      try {
        metadata = await lstat(lockPath);
      } catch (error) {
        if (errorCode(error) !== "ENOENT") return undefined;
        try {
          await rename(claimPath, lockPath);
          published = true;
          return async () => {
            let removedOwner = false;
            try {
              await unlink(path.join(lockPath, ownerName));
              removedOwner = true;
            } catch {
              // A stale cleaner may already have removed this generation.
            }
            if (removedOwner) await rmdir(lockPath).catch(() => undefined);
          };
        } catch (renameError) {
          if (!isLockContention(renameError)) return undefined;
          await delay(LOCK_POLL_MS);
          continue;
        }
      }

      const owned = typeof process.getuid !== "function" || metadata.uid === process.getuid();
      if (!metadata.isDirectory()
        || metadata.isSymbolicLink()
        || !owned
        || (metadata.mode & 0o077) !== 0) {
        return undefined;
      }

      if (Date.now() - metadata.mtimeMs > STALE_LOCK_MS) {
        let entries: string[];
        try {
          entries = await readdir(lockPath);
        } catch (error) {
          if (errorCode(error) === "ENOENT") continue;
          return undefined;
        }

        if (entries.length === 0) {
          // Legacy locks have no owner token. Only stale, empty legacy locks
          // are recoverable; a recent legacy process keeps its full lease.
          await rmdir(lockPath).catch(() => undefined);
          continue;
        }

        if (entries.length === 1) {
          const ownerEntry = entries[0];
          const staleOwnerToken = ownerEntry && LOCK_OWNER_PATTERN.exec(ownerEntry)?.[1];
          if (ownerEntry && staleOwnerToken) {
            const staleOwnerPath = path.join(lockPath, ownerEntry);
            try {
              const ownerMetadata = await lstat(staleOwnerPath);
              const ownerOwned =
                typeof process.getuid !== "function" || ownerMetadata.uid === process.getuid();
              // The directory path may now name a replacement generation.
              // Its independently fresh owner must never inherit the stale directory observation.
              if (ownerMetadata.isFile()
                && !ownerMetadata.isSymbolicLink()
                && ownerOwned
                && (ownerMetadata.mode & 0o077) === 0
                && Date.now() - ownerMetadata.mtimeMs > STALE_LOCK_MS
                && ownerMetadata.size === staleOwnerToken.length
                && await readFile(staleOwnerPath, "utf8") === staleOwnerToken) {
                await unlink(staleOwnerPath);
                await rmdir(lockPath).catch(() => undefined);
                continue;
              }
            } catch (error) {
              if (errorCode(error) === "ENOENT") continue;
              return undefined;
            }
          }
        }
      }
      await delay(LOCK_POLL_MS);
    }
    return undefined;
  } finally {
    await handle?.close().catch(() => undefined);
    if (!published && claimCreated) {
      if (ownerCreated) {
        await unlink(path.join(claimPath, ownerName)).catch(() => undefined);
      }
      await rmdir(claimPath).catch(() => undefined);
    }
  }
}

function errorCode(error: unknown): string | undefined {
  return error !== null && typeof error === "object" && "code" in error
    ? String(error.code)
    : undefined;
}

function isLockContention(error: unknown): boolean {
  const code = errorCode(error);
  return code === "EEXIST" || code === "ENOTEMPTY";
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
