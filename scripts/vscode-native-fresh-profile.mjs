import assert from "node:assert/strict";
import { access, chmod, lstat, mkdir, realpath } from "node:fs/promises";
import path from "node:path";

const HUMAN_UI_FLAG = "SILMARIL_VSCODE_QA_ALLOW_HUMAN_UI";
const SESSION_ROUTE_ENV = "SILMARIL_NATIVE_SESSION_ROUTE";
const SHARED_COPILOT_ROUTE = "shared-copilot";
const HANDOFF_ENV = Object.freeze({
  trust: "NATIVE_TRUST_PENDING_PATH",
  disableAi: "NATIVE_AGENT_ENABLE_PENDING_PATH",
  workspaceAi: "NATIVE_WORKSPACE_AI_ENABLE_PENDING_PATH",
  sharedModel: "NATIVE_SHARED_MODEL_PENDING_PATH",
});
const CHILD_ENV_ALLOWLIST = Object.freeze([
  "PATH",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "USER",
  "LOGNAME",
  "SHELL",
]);
const DARWIN_UNIX_SOCKET_PATH_MAX_BYTES = 103;
const VSCODE_MAIN_IPC_BASENAME = "1.14-main.sock";

export function pathIsWithin(root, candidate) {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === "" || (
    relative !== ".."
    && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative)
  );
}

export function resolvePortableQaPolicy(env = process.env) {
  const flag = env[HUMAN_UI_FLAG];
  const configuredRoute = env[SESSION_ROUTE_ENV];
  assert.ok(
    flag === undefined || flag === "1",
    `${HUMAN_UI_FLAG} must be omitted or exactly 1`,
  );
  assert.ok(
    configuredRoute === undefined || configuredRoute === SHARED_COPILOT_ROUTE,
    `${SESSION_ROUTE_ENV} must be omitted or exactly ${SHARED_COPILOT_ROUTE}`,
  );
  const sessionRoute = configuredRoute ?? "legacy-local";
  const handoffs = Object.fromEntries(
    Object.entries(HANDOFF_ENV).map(([name, envName]) => [
      name,
      env[envName],
    ]),
  );
  if (flag !== "1") {
    for (const [name, handoffPath] of Object.entries(handoffs)) {
      assert.equal(
        handoffPath,
        undefined,
        `Preflight-only mode must not provide the ${name} handoff`,
      );
    }
    return {
      mode: "preflight",
      sessionRoute,
      allowLaunch: false,
      allowNormalTrustHandoff: false,
      allowUiEnableHandoff: false,
      requireSharedModelHandoff: false,
      handoffs,
    };
  }
  const requiredHandoffs = sessionRoute === SHARED_COPILOT_ROUTE
    ? new Set(Object.keys(HANDOFF_ENV))
    : new Set(["trust", "disableAi", "workspaceAi"]);
  for (const [name, handoffPath] of Object.entries(handoffs)) {
    if (!requiredHandoffs.has(name)) {
      assert.equal(
        handoffPath,
        undefined,
        `Legacy Local mode must not provide the ${name} handoff`,
      );
      continue;
    }
    assert.ok(
      handoffPath && path.isAbsolute(handoffPath),
      `Human-UI mode requires an absolute ${name} handoff path`,
    );
  }
  assert.equal(
    new Set(
      Object.values(handoffs)
        .filter((value) => value !== undefined)
        .map((value) => path.resolve(value)),
    ).size,
    requiredHandoffs.size,
    "Human-UI handoff paths must be distinct",
  );
  return {
    mode: "human-ui",
    sessionRoute,
    allowLaunch: true,
    allowNormalTrustHandoff: true,
    allowUiEnableHandoff: true,
    requireSharedModelHandoff: sessionRoute === SHARED_COPILOT_ROUTE,
    handoffs,
  };
}

async function pathExists(filePath) {
  return await access(filePath).then(() => true).catch((error) => {
    if (error?.code === "ENOENT") return false;
    throw error;
  });
}

export async function createFreshQaLayout({
  privateRoot,
  receiptPath,
  policy,
}) {
  assert.ok(
    privateRoot && path.isAbsolute(privateRoot),
    "VSCODE_NATIVE_PRIVATE_ROOT must be absolute",
  );
  assert.ok(
    receiptPath && path.isAbsolute(receiptPath),
    "NATIVE_QUALIFICATION_RECEIPT must be absolute",
  );
  const resolvedRoot = path.resolve(privateRoot);
  const resolvedReceipt = path.resolve(receiptPath);
  const mainIpcPath = path.join(
    resolvedRoot,
    "user-data",
    VSCODE_MAIN_IPC_BASENAME,
  );
  const mainIpcPathBytes = Buffer.byteLength(mainIpcPath, "utf8");
  assert.ok(
    mainIpcPathBytes <= DARWIN_UNIX_SOCKET_PATH_MAX_BYTES,
    `VS Code macOS IPC path is ${mainIpcPathBytes} UTF-8 bytes; maximum is ${DARWIN_UNIX_SOCKET_PATH_MAX_BYTES}. Choose a shorter owned real path such as /private/tmp/private-parent/run; do not use a symlink alias.`,
  );
  assert.equal(
    pathIsWithin(resolvedRoot, resolvedReceipt)
      && resolvedReceipt !== resolvedRoot,
    true,
    "Qualification receipt must be strictly inside the fresh QA root",
  );
  const outputPaths = [resolvedReceipt];
  for (const [name, handoffPath] of Object.entries(policy.handoffs)) {
    if (!handoffPath) continue;
    const resolvedHandoff = path.resolve(handoffPath);
    assert.equal(
      pathIsWithin(resolvedRoot, resolvedHandoff)
        && resolvedHandoff !== resolvedRoot,
      true,
      `${name} handoff must be strictly inside the fresh QA root`,
    );
    outputPaths.push(resolvedHandoff);
  }
  assert.equal(
    new Set(outputPaths).size,
    outputPaths.length,
    "Qualification receipt and handoff paths must be distinct",
  );
  assert.equal(
    await pathExists(privateRoot),
    false,
    "Fresh QA root already exists",
  );
  const parent = path.dirname(privateRoot);
  const parentInfo = await lstat(parent);
  assert.equal(parentInfo.isSymbolicLink(), false, "QA parent must not be a symlink");
  assert.equal(parentInfo.isDirectory(), true, "QA parent must be a directory");
  if (typeof process.getuid === "function") {
    assert.equal(parentInfo.uid, process.getuid(), "QA parent is not owned by this user");
  }
  assert.equal(
    await realpath(parent),
    path.resolve(parent),
    "QA parent must not resolve through a symlink",
  );
  await mkdir(privateRoot, { mode: 0o700 });
  await chmod(privateRoot, 0o700);
  const rootInfo = await lstat(privateRoot);
  assert.equal(rootInfo.isSymbolicLink(), false);
  assert.equal(rootInfo.isDirectory(), true);
  if (typeof process.getuid === "function") {
    assert.equal(rootInfo.uid, process.getuid());
  }
  const root = await realpath(privateRoot);
  assert.equal(root, path.resolve(privateRoot));
  return {
    root,
    receiptPath: resolvedReceipt,
    home: path.join(root, "home"),
    userData: path.join(root, "user-data"),
    extensions: path.join(root, "extensions"),
    workspace: path.join(root, "workspace"),
    temporary: path.join(root, "tmp"),
    evidence: path.join(root, "evidence"),
    candidate: path.join(root, "candidate-0.3.1"),
    workspaceFile: path.join(root, "native-qa.code-workspace"),
  };
}

export function buildMinimalChildEnvironment(source, overrides) {
  const child = {};
  for (const name of CHILD_ENV_ALLOWLIST) {
    if (typeof source[name] === "string") child[name] = source[name];
  }
  return Object.assign(child, overrides);
}

