import { randomInt, randomUUID } from "node:crypto";
import type { Stats } from "node:fs";
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
} from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const MAX_WORKSPACES = 256;
const MAX_FILE_BYTES = 64 * 1_024;
const LOCK_WAIT_MS = 1_000;
const LOCK_POLL_MS = 10;
const STALE_LOCK_MS = 30_000;
const MAX_PROCESS_PID = 2_147_483_647;
const PID_LOCK_OWNER_PATTERN =
  /^owner-([1-9][0-9]{0,9})-([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/u;
const LEGACY_LOCK_OWNER_PATTERN =
  /^owner-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

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
  const ownerName = `owner-${process.pid}-${randomUUID()}`;
  let recoveringDirectory: Stats | undefined;
  while (Date.now() <= deadline) {
    let metadata: Stats;
    let created = false;
    try {
      await mkdir(lockPath, { mode: 0o700 });
      created = true;
      metadata = await lstat(lockPath);
    } catch (error) {
      if (created) {
        if (errorCode(error) === "ENOENT") continue;
        return undefined;
      }
      if (errorCode(error) !== "EEXIST") return undefined;
      try {
        metadata = await lstat(lockPath);
      } catch (lstatError) {
        if (errorCode(lstatError) === "ENOENT") continue;
        return undefined;
      }
    }

    if (!isPrivateOwnedDirectory(metadata)) return undefined;

    if (created) {
      const result = await publishRegistryLockOwner(lockPath, metadata, ownerName);
      if (result === "acquired") return registryLockRelease(lockPath, ownerName);
      if (result === "abort") return undefined;
      await delay(LOCK_POLL_MS);
      continue;
    }

    if (Date.now() - metadata.mtimeMs > STALE_LOCK_MS
      || (recoveringDirectory && sameDirectory(recoveringDirectory, metadata))) {
      // A competing marker can refresh this directory's mtime. Keep recovery
      // eligibility for the same stale generation while retries are bounded.
      recoveringDirectory = metadata;
      let entries: string[];
      try {
        entries = await readdir(lockPath);
      } catch (error) {
        if (errorCode(error) === "ENOENT") continue;
        return undefined;
      }

      for (const entry of entries) {
        const owner = parseLockOwner(entry);
        if (!owner) continue;
        const ownerPath = path.join(lockPath, entry);
        try {
          const ownerMetadata = await lstat(ownerPath);
          // Pre-PID owners retain the age-only recovery behavior. PID owners
          // are recoverable only when signal 0 proves their process is gone.
          // A reused PID is intentionally treated as a live owner.
          if (isPrivateOwnedDirectory(ownerMetadata)
            && Date.now() - ownerMetadata.mtimeMs > STALE_LOCK_MS
            && (owner.kind === "legacy" || !processExists(owner.pid))) {
            await rmdir(ownerPath);
          }
        } catch (error) {
          if (errorCode(error) !== "ENOENT") return undefined;
        }
      }
      // Adopt the same stale directory after reclaiming any old markers.
      // Keeping it in place prevents a competing legacy mkdir from succeeding.
      if (entries.length === 0 || (await readdir(lockPath).catch(() => entries)).length === 0) {
        const result = await publishRegistryLockOwner(lockPath, metadata, ownerName);
        if (result === "acquired") return registryLockRelease(lockPath, ownerName);
        if (result === "abort") return undefined;
        // Stagger attempts when two recoverers both relinquished their markers.
        await delay(LOCK_POLL_MS + randomInt(LOCK_POLL_MS));
        continue;
      }
    }
    await delay(LOCK_POLL_MS);
  }
  return undefined;
}

async function publishRegistryLockOwner(
  lockPath: string,
  observedDirectory: Stats,
  ownerName: string,
): Promise<"acquired" | "retry" | "abort"> {
  const ownerPath = path.join(lockPath, ownerName);
  try {
    // mkdir publishes the whole marker atomically, even if the hook is interrupted.
    await mkdir(ownerPath, { mode: 0o700 });
  } catch (error) {
    return errorCode(error) === "ENOENT" ? "retry" : "abort";
  }

  try {
    const currentDirectory = await lstat(lockPath);
    const entries = await readdir(lockPath);
    if (sameDirectory(observedDirectory, currentDirectory)
      && isPrivateOwnedDirectory(currentDirectory)
      && entries.length === 1
      && entries[0] === ownerName) {
      return "acquired";
    }
  } catch (error) {
    if (errorCode(error) !== "ENOENT") {
      await rmdir(ownerPath).catch(() => undefined);
      return "abort";
    }
  }

  try {
    await rmdir(ownerPath);
  } catch (error) {
    if (errorCode(error) !== "ENOENT") return "abort";
  }
  return "retry";
}

function registryLockRelease(lockPath: string, ownerName: string): () => Promise<void> {
  return async () => {
    let removedOwner = false;
    try {
      await rmdir(path.join(lockPath, ownerName));
      removedOwner = true;
    } catch {
      // A stale cleaner may already have removed this generation.
    }
    if (removedOwner) await rmdir(lockPath).catch(() => undefined);
  };
}

function isPrivateOwnedDirectory(metadata: Stats): boolean {
  const owned = typeof process.getuid !== "function" || metadata.uid === process.getuid();
  return metadata.isDirectory()
    && !metadata.isSymbolicLink()
    && owned
    && (metadata.mode & 0o077) === 0;
}

function sameDirectory(
  observed: Stats,
  current: Stats,
): boolean {
  return observed.dev === current.dev
    && observed.ino !== 0
    && observed.ino === current.ino
    && observed.birthtimeMs === current.birthtimeMs;
}

function errorCode(error: unknown): string | undefined {
  return error !== null && typeof error === "object" && "code" in error
    ? String(error.code)
    : undefined;
}

function parseLockOwner(
  entry: string,
): { kind: "legacy" } | { kind: "pid"; pid: number } | undefined {
  if (LEGACY_LOCK_OWNER_PATTERN.test(entry)) return { kind: "legacy" };
  const match = PID_LOCK_OWNER_PATTERN.exec(entry);
  if (!match) return undefined;
  const pid = Number(match[1]);
  if (!Number.isSafeInteger(pid)
    || pid < 1
    || pid > MAX_PROCESS_PID
    || String(pid) !== match[1]) {
    return undefined;
  }
  return { kind: "pid", pid };
}

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM and unknown failures cannot prove that the process exited.
    return errorCode(error) !== "ESRCH";
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
