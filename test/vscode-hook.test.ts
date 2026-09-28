import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmod, mkdtemp, readFile, realpath, stat, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  PLUGIN_VERSION,
  SAFE_BLOCK_MESSAGE,
  SAFE_WARN_MESSAGE,
  buildHookTarget,
  effectiveMode,
  governanceContext,
  isBlockCandidate,
  runVSCodeHook,
  withProvenance,
  type VSCodeEventName,
} from "../src/vscode-hook.ts";
import {
  buildLocalProtectionEvent,
  writeLocalProtectionEvent,
} from "../src/local-evidence.ts";
import { resolveRuntimeConfig } from "../src/runtime-config.ts";
import { observationPath, recordObservedWorkspace } from "../src/workspace-observation.ts";

const MISSING_CONFIG = path.join(os.tmpdir(), "silmaril-vscode-missing", "settings.json");
const BASE_ENV = {
  SILMARIL_CONFIG_PATH: MISSING_CONFIG,
  SILMARIL_API_KEY: "test-key",
  SILMARIL_API_URL: "https://firewall.example/classify",
  SILMARIL_ENDPOINT_ID: "2b64e603-f82a-4aec-9524-9736472dc80a",
  SILMARIL_TIMEOUT_MS: "2500",
  SILMARIL_BLOCK_MALICIOUS: "false",
  SILMARIL_DEBUG: "false",
};

function dependencies(
  results: Array<Record<string, unknown> | Error>,
  events: unknown[] = [],
  calls: unknown[] = [],
) {
  class FakeFirewall {
    constructor(options: unknown) {
      calls.push({ constructor: options });
    }

    async classify(text: string, options: unknown) {
      calls.push({ text, options });
      const result = results.shift();
      if (result instanceof Error) throw result;
      return result ?? { prediction: "BENIGN", score: 0.01, threshold: 0.5 };
    }
  }
  return {
    firewallConstructor: FakeFirewall,
    evidenceEmitter: async (event: unknown) => { events.push(event); },
    workspaceObserver: async () => undefined,
  };
}

function payload(event: VSCodeEventName): Record<string, unknown> {
  const base = {
    hook_event_name: event,
    session_id: "session-1",
    timestamp: "2026-08-26T00:00:00Z",
    cwd: "/tmp/project",
    transcript_path: "/tmp/ignored-transcript.jsonl",
  };
  switch (event) {
    case "SessionStart":
      return { ...base, source: "new" };
    case "UserPromptSubmit":
      return { ...base, prompt: "user prompt" };
    case "PreToolUse":
      return {
        ...base,
        tool_name: "runTerminalCommand",
        tool_input: { command: "pwd" },
        tool_use_id: "tool-1",
      };
    case "PostToolUse":
      return {
        ...base,
        tool_name: "runTerminalCommand",
        tool_input: { command: "pwd" },
        tool_response: "tool result",
        tool_use_id: "tool-1",
      };
  }
}

test("explicit mode wins and governance actions are block candidates", () => {
  assert.equal(effectiveMode({ prediction: "MALICIOUS", mode: "block" }, "shadow"), "shadow");
  assert.equal(effectiveMode({ prediction: "BENIGN", mode: "warn" }), "warn");
  assert.equal(effectiveMode({ prediction: "BENIGN" }), "shadow");
  assert.equal(isBlockCandidate({ prediction: "BENIGN", governance: { action: "block" } }), true);
  assert.equal(isBlockCandidate({ prediction: "MALICIOUS", governance: { action: "allow" } }), true);
});

test("runtime configuration requires a private schema-v1 file when present", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-vscode-config-"));
  const filePath = path.join(root, "silmaril-firewall.json");
  await writeFile(filePath, JSON.stringify({
    schemaVersion: 1,
    enabled: true,
    apiKey: "file-key",
    apiUrl: "https://file.example/classify",
    endpointId: "2b64e603-f82a-4aec-9524-9736472dc80a",
    timeoutMs: 375,
    mode: "warn",
    blockMalicious: false,
    debug: true,
  }), { mode: 0o600 });
  assert.deepEqual(resolveRuntimeConfig({ SILMARIL_CONFIG_PATH: filePath }), {
    apiKey: "file-key",
    apiUrl: "https://file.example/classify",
    endpointId: "2b64e603-f82a-4aec-9524-9736472dc80a",
    timeoutMs: 375,
    mode: "warn",
    blockMalicious: false,
    debug: true,
  });
  await chmod(filePath, 0o644);
  assert.equal(resolveRuntimeConfig({ ...BASE_ENV, SILMARIL_CONFIG_PATH: filePath }), undefined);
  await chmod(filePath, 0o600);
  const linked = path.join(root, "linked.json");
  await symlink(filePath, linked);
  assert.equal(resolveRuntimeConfig({ SILMARIL_CONFIG_PATH: linked }), undefined);
  await writeFile(filePath, JSON.stringify({ schemaVersion: 2 }), { mode: 0o600 });
  assert.equal(resolveRuntimeConfig({ SILMARIL_CONFIG_PATH: filePath }), undefined);
});

test("shadow classifies each current native content boundary exactly once", async () => {
  const events: any[] = [];
  const calls: any[] = [];
  const deps = dependencies(
    Array.from({ length: 3 }, () => ({ prediction: "MALICIOUS", score: 0.9, threshold: 0.5 })),
    events,
    calls,
  );
  for (const event of ["UserPromptSubmit", "PreToolUse", "PostToolUse"] as const) {
    assert.deepEqual(await runVSCodeHook(event, payload(event), BASE_ENV, deps), {});
  }
  assert.deepEqual(
    calls.filter((call) => call.text).map((call) => call.options.hook),
    ["user_input", "tool_call", "tool_response"],
  );
  assert.ok(calls.filter((call) => call.text).every(
    (call) => call.options.metadata.silmaril.provenance.harness === "vscode",
  ));
  assert.ok(events.every((event) => event.mode === "shadow" && event.policyDecision === "monitor"));
  assert.doesNotMatch(JSON.stringify(events), /user prompt|tool result|pwd|session-1/u);
});

test("warn returns one fixed warning and continues on every classifiable boundary", async () => {
  const malicious = { prediction: "MALICIOUS", mode: "warn", score: 0.99 };
  const events: any[] = [];
  const backendControlledEnv: Record<string, string> = { ...BASE_ENV };
  delete backendControlledEnv.SILMARIL_BLOCK_MALICIOUS;

  assert.deepEqual(
    await runVSCodeHook(
      "UserPromptSubmit",
      payload("UserPromptSubmit"),
      backendControlledEnv,
      dependencies([malicious], events),
    ),
    { continue: true, systemMessage: SAFE_WARN_MESSAGE },
  );
  for (const event of ["PreToolUse", "PostToolUse"] as const) {
    assert.deepEqual(
      await runVSCodeHook(event, payload(event), backendControlledEnv, dependencies([malicious], events)),
      {
        continue: true,
        systemMessage: SAFE_WARN_MESSAGE,
        hookSpecificOutput: {
          hookEventName: event,
          additionalContext: SAFE_WARN_MESSAGE,
        },
      },
    );
  }
  assert.ok(events.every((event) => (
    event.policyDecision === "warn"
    && event.nativeAction === "warning_context_returned"
    && event.warnDelivery === "delivered"
  )));
});

test("block uses VS Code native pre-execution and continuation controls", async () => {
  const malicious = { prediction: "MALICIOUS", primaryOutcome: "code_execution" };
  const env = { ...BASE_ENV, SILMARIL_MODE: "block" };
  const events: any[] = [];

  assert.deepEqual(
    await runVSCodeHook("UserPromptSubmit", payload("UserPromptSubmit"), env, dependencies([malicious], events)),
    { continue: false, stopReason: SAFE_BLOCK_MESSAGE },
  );
  assert.deepEqual(
    await runVSCodeHook("PreToolUse", payload("PreToolUse"), env, dependencies([malicious], events)),
    {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: SAFE_BLOCK_MESSAGE,
      },
    },
  );
  const postToolOutput = await runVSCodeHook(
    "PostToolUse",
    payload("PostToolUse"),
    env,
    dependencies([malicious], events),
  );
  assert.deepEqual(postToolOutput, { decision: "block", reason: SAFE_BLOCK_MESSAGE });
  assert.doesNotMatch(JSON.stringify(postToolOutput), /tool result/u);
  assert.ok(events.every((event) => (
    event.policyDecision === "block"
    && event.nativeAction === "block_returned"
    && event.outcome === "not_observed"
  )));
});

test("governance and provenance use one VS Code host identity", () => {
  const userTarget = buildHookTarget("UserPromptSubmit", payload("UserPromptSubmit"));
  const toolTarget = buildHookTarget("PreToolUse", {
    ...payload("PreToolUse"),
    tool_name: "mcp__github__create_issue",
  });
  assert.ok(userTarget && toolTarget);
  assert.deepEqual(governanceContext(userTarget), {
    agent: "vscode",
    resource: { kind: "agent", id: "vscode" },
  });
  assert.deepEqual(governanceContext(toolTarget), {
    agent: "vscode",
    resource: { kind: "mcp_tool", id: "create_issue", parent_id: "github" },
  });
  assert.deepEqual(withProvenance({
    silmaril: { provenance: { harness: "spoofed", device_name: "spoofed-host" } },
  }, "2b64e603-f82a-4aec-9524-9736472dc80a"), {
    silmaril: {
      provenance: {
        schema_version: 1,
        endpoint_id: "2b64e603-f82a-4aec-9524-9736472dc80a",
        harness: "vscode",
      },
    },
  });
  assert.deepEqual(withProvenance({
    trace: "keep",
    silmaril: { integration: "silmaril-vscode-firewall", provenance: { device_name: "spoofed-host", endpoint_id: "spoofed" } },
  }, undefined, undefined, "  Office Mac \n"), {
    trace: "keep",
    silmaril: {
      integration: "silmaril-vscode-firewall",
      provenance: {
        schema_version: 1,
        harness: "vscode",
        device_name: "Office Mac",
      },
    },
  });
});

test("transcripts and lifecycle-only events are never reconstructed", async () => {
  const calls: any[] = [];
  assert.deepEqual(
    await runVSCodeHook("SessionStart", payload("SessionStart"), BASE_ENV, dependencies([], [], calls)),
    {},
  );
  assert.equal(calls.filter((call) => call.text).length, 0);
  assert.equal(buildHookTarget("UserPromptSubmit", {
    ...payload("UserPromptSubmit"),
    hook_event_name: "Stop",
  }), undefined);
});

test("classification and evidence failures always fail open", async () => {
  assert.deepEqual(
    await runVSCodeHook(
      "PreToolUse",
      payload("PreToolUse"),
      { ...BASE_ENV, SILMARIL_MODE: "block" },
      dependencies([new Error("network failure")]),
    ),
    {},
  );
  const evidenceFailure = await runVSCodeHook(
    "PreToolUse",
    payload("PreToolUse"),
    { ...BASE_ENV, SILMARIL_MODE: "block" },
    {
      ...dependencies([{ prediction: "MALICIOUS" }]),
      evidenceEmitter: async () => { throw new Error("disk failure"); },
    },
  );
  assert.equal((evidenceFailure.hookSpecificOutput as Record<string, unknown>).permissionDecision, "deny");

  const cli = spawnSync(
    process.execPath,
    [new URL("../dist/vscode-hook.js", import.meta.url).pathname, "PreToolUse"],
    { input: "not-json", encoding: "utf8" },
  );
  assert.equal(cli.status, 0);
  assert.deepEqual(JSON.parse(cli.stdout), {});
});

test("runtime markers are stable and local evidence is private and raw-content free", async () => {
  const marker = "silmaril-runtime-check:12345678-1234-4123-8123-123456789abc";
  const target = buildHookTarget("UserPromptSubmit", {
    ...payload("UserPromptSubmit"),
    prompt: `Verify ${marker}`,
  });
  assert.equal(target?.requestFingerprint, createHash("sha256").update(marker).digest("hex"));

  const root = await mkdtemp(path.join(os.tmpdir(), "silmaril-vscode-evidence-"));
  const event = buildLocalProtectionEvent({
    pluginVersion: PLUGIN_VERSION,
    hook: "pre_tool",
    mode: "block",
    requestFingerprint: "request-fingerprint",
    sessionId: "raw-session-id",
    toolName: "runTerminalCommand",
    classification: {
      prediction: "MALICIOUS",
      primaryOutcome: "code_execution",
      raw: "must-not-leak",
    },
    policyDecision: "block",
    nativeAction: "block_returned",
  });
  const destination = await writeLocalProtectionEvent(event, { SILMARIL_LOCAL_EVENT_DIR: root });
  assert.ok(destination);
  const encoded = await readFile(destination, "utf8");
  assert.doesNotMatch(encoded, /must-not-leak|raw-session-id/u);
  assert.equal((await stat(destination)).mode & 0o777, 0o600);
  assert.equal((await stat(root)).mode & 0o777, 0o700);
});

test("workspace observations are bounded private local paths, not payload copies", async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), "silmaril-vscode-workspace-"));
  const workspace = await mkdtemp(path.join(os.tmpdir(), "silmaril-vscode-project-"));
  const destination = path.join(stateRoot, "observed-workspaces.json");
  await recordObservedWorkspace(workspace, { SILMARIL_VSCODE_WORKSPACE_STATE: destination });
  const parsed = JSON.parse(await readFile(destination, "utf8"));
  assert.equal(parsed.schemaVersion, 1);
  assert.equal(parsed.workspaces[0].path, await realpath(workspace));
  assert.equal((await stat(destination)).mode & 0o777, 0o600);
  assert.equal(observationPath({ SILMARIL_VSCODE_WORKSPACE_STATE: destination }), destination);
});

test("concurrent workspace observations preserve every workspace", async () => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), "silmaril-vscode-workspace-race-"));
  const destination = path.join(stateRoot, "observed-workspaces.json");
  const workspaces = await Promise.all(Array.from({ length: 24 }, async (_, index) => (
    mkdtemp(path.join(os.tmpdir(), `silmaril-vscode-project-${index}-`))
  )));

  await Promise.all(workspaces.map((workspace) => recordObservedWorkspace(
    workspace,
    { SILMARIL_VSCODE_WORKSPACE_STATE: destination },
  )));

  const parsed = JSON.parse(await readFile(destination, "utf8"));
  const observed = new Set(parsed.workspaces.map((item: { path: string }) => item.path));
  assert.deepEqual(
    observed,
    new Set(await Promise.all(workspaces.map((workspace) => realpath(workspace)))),
  );
});

test("manifests are Agent Plugins 1.0 native and version aligned", async () => {
  const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  const pluginJson = JSON.parse(await readFile(new URL("../plugin.json", import.meta.url), "utf8"));
  const hooks = JSON.parse(await readFile(
    new URL("../com.github.copilot/hooks/hooks.json", import.meta.url),
    "utf8",
  ));
  const launcher = await readFile(
    new URL("../scripts/run-hook.sh", import.meta.url),
    "utf8",
  );
  assert.equal(packageJson.version, "0.1.1");
  assert.equal(pluginJson.$schema, "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json");
  assert.equal(pluginJson.name, "silmaril-vscode-firewall");
  assert.equal(pluginJson.version, packageJson.version);
  assert.equal(packageJson.dependencies["@silmaril-security/sdk"], "0.6.2");
  assert.deepEqual(Object.keys(hooks.hooks), [
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
  ]);
  assert.ok(Object.values(hooks.hooks).every((entries: any) => (
    entries[0].osx.includes("${PLUGIN_ROOT}/scripts/run-hook.sh")
    && entries[0].command === undefined
    && entries[0].linux === undefined
    && entries[0].windows === undefined
  )));
  assert.match(launcher, /stat -f '%u %Lp'/u);
  assert.match(launcher, /\[ -L "\$\{runtime_file\}" \]/u);
  assert.match(launcher, /\[ -L "\$\{node_path\}" \]/u);
});

test("classify metadata includes the mac computer name without an endpoint id", async () => {
  const calls: any[] = [];
  const events: any[] = [];
  const env: Record<string, string> = { ...BASE_ENV, SILMARIL_DEBUG: "true" };
  delete env.SILMARIL_ENDPOINT_ID;
  const stderr = await captureStderr(async () => {
    assert.deepEqual(
      await runVSCodeHook("UserPromptSubmit", payload("UserPromptSubmit"), env, {
        ...dependencies([{ prediction: "BENIGN" }], events, calls),
        deviceName: () => "  Office Mac \n",
      }),
      {},
    );
  });
  const metadata = calls.find((call) => call.text).options.metadata;
  assert.deepEqual(metadata.silmaril.provenance, {
    schema_version: 1,
    harness: "vscode",
    device_name: "Office Mac",
  });
  assert.deepEqual(metadata.silmaril.governance, {
    agent: "vscode",
    resource: { kind: "agent", id: "vscode" },
  });
  assert.doesNotMatch(JSON.stringify(events), /Office Mac/u);
  assert.doesNotMatch(stderr, /Office Mac/u);
});

test("invalid or failed device-name lookup still classifies and drops spoofed metadata", async () => {
  const calls: any[] = [];
  const events: any[] = [];
  const env = { ...BASE_ENV, SILMARIL_DEBUG: "true" };
  const stderr = await captureStderr(async () => {
    assert.deepEqual(
      await runVSCodeHook("UserPromptSubmit", payload("UserPromptSubmit"), env, {
        ...dependencies([{ prediction: "BENIGN" }], events, calls),
        deviceName: () => {
          throw new Error("scutil failed for Office Mac");
        },
      }),
      {},
    );
    for (const deviceName of ["Office\u0000Mac", "Office\u007FMac", "Office\u0085Mac"]) {
      assert.deepEqual(
        await runVSCodeHook("PreToolUse", payload("PreToolUse"), env, {
          ...dependencies([{ prediction: "BENIGN" }], events, calls),
          deviceName: () => deviceName,
        }),
        {},
      );
    }
  });
  const provenances = calls.filter((call) => call.text).map((call) => call.options.metadata.silmaril.provenance);
  assert.equal(provenances.length, 4);
  assert.ok(provenances.every((provenance: { device_name?: string; harness: string; endpoint_id: string }) => (
    provenance.device_name === undefined
    && provenance.harness === "vscode"
    && provenance.endpoint_id === "2b64e603-f82a-4aec-9524-9736472dc80a"
  )));
  assert.doesNotMatch(JSON.stringify(events), /Office Mac/u);
  assert.doesNotMatch(stderr, /Office Mac/u);
});

async function captureStderr(run: () => Promise<void>): Promise<string> {
  const chunks: string[] = [];
  const original = process.stderr.write;
  process.stderr.write = ((chunk: string | Uint8Array) => {
    chunks.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
    return true;
  }) as typeof process.stderr.write;
  try {
    await run();
  } finally {
    process.stderr.write = original;
  }
  return chunks.join("");
}
