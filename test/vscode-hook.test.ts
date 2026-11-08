import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmod, copyFile, mkdir, mkdtemp, readFile, realpath, stat, symlink, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { Firewall } from "@silmaril-security/sdk";
import {
  PLUGIN_VERSION,
  SAFE_BLOCK_MESSAGE,
  SAFE_WARN_MESSAGE,
  buildHookTarget,
  dispatchVSCodeHook,
  effectiveMode,
  governanceContext,
  isBlockCandidate,
  runVSCodeCopilotHook,
  runVSCodeHook,
  withProvenance,
  type RuntimeDependencies,
  type VSCodeCopilotEventName,
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

function copilotPayload(event: VSCodeCopilotEventName): Record<string, unknown> {
  const base = {
    sessionId: "session-1",
    timestamp: 1_788_307_200_000,
    cwd: "/tmp/project",
  };
  switch (event) {
    case "sessionStart":
      return { ...base, source: "new" };
    case "userPromptSubmitted":
      return { ...base, prompt: "user prompt" };
    case "preToolUse":
      return {
        ...base,
        toolName: "runTerminalCommand",
        toolArgs: { command: "pwd" },
      };
    case "postToolUse":
      return {
        ...base,
        toolName: "runTerminalCommand",
        toolArgs: { command: "pwd" },
        toolResult: {
          resultType: "success",
          textResultForLlm: "tool result",
        },
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

test("dispatch selects one validated nonmixed runtime schema and classifies once", async () => {
  const calls: any[] = [];
  const deps = dependencies(
    Array.from({ length: 2 }, () => ({ prediction: "BENIGN", score: 0.01, threshold: 0.5 })),
    [],
    calls,
  );
  assert.deepEqual(
    await dispatchVSCodeHook("preToolUse", payload("PreToolUse"), BASE_ENV, deps),
    {},
  );
  assert.deepEqual(
    await dispatchVSCodeHook("preToolUse", copilotPayload("preToolUse"), BASE_ENV, deps),
    {},
  );
  const classifications = calls.filter((call) => call.text);
  assert.equal(classifications.length, 2);
  assert.deepEqual(
    classifications.map((call) => call.options.metadata.vscodeHookRuntime),
    ["local", "copilot"],
  );
  assert.deepEqual(
    classifications.map((call) => call.options.metadata.vscodeHookEvent),
    ["PreToolUse", "preToolUse"],
  );

  const rejected = [
    { ...copilotPayload("preToolUse"), sessionId: "" },
    { ...copilotPayload("preToolUse"), session_id: "mixed" },
    { ...payload("PreToolUse"), sessionId: "mixed" },
    { ...payload("PreToolUse"), hook_event_name: "PostToolUse" },
    { ...copilotPayload("preToolUse"), timestamp: "2026-08-26T00:00:00Z" },
  ];
  for (const input of rejected) {
    assert.deepEqual(await dispatchVSCodeHook("preToolUse", input, BASE_ENV, deps), {});
  }
  assert.equal(calls.filter((call) => call.text).length, 2);
  assert.deepEqual(
    await runVSCodeCopilotHook("preToolUse", payload("PreToolUse"), BASE_ENV, deps),
    {},
  );
  assert.deepEqual(
    await runVSCodeHook("PreToolUse", copilotPayload("preToolUse"), BASE_ENV, deps),
    {},
  );
  assert.equal(calls.filter((call) => call.text).length, 2);
});

test("request IDs preserve native Copilot timestamps and Local tool IDs", async () => {
  const calls: any[] = [];
  const deps = dependencies(
    Array.from({ length: 7 }, () => ({ prediction: "BENIGN", score: 0.01, threshold: 0.5 })),
    [],
    calls,
  );
  const shared = copilotPayload("userPromptSubmitted");
  await runVSCodeCopilotHook("userPromptSubmitted", shared, BASE_ENV, deps);
  await runVSCodeCopilotHook("userPromptSubmitted", { ...shared }, BASE_ENV, deps);
  await runVSCodeCopilotHook("userPromptSubmitted", {
    ...shared,
    timestamp: (shared.timestamp as number) + 1,
  }, BASE_ENV, deps);

  const localTool = payload("PreToolUse");
  await runVSCodeHook("PreToolUse", localTool, BASE_ENV, deps);
  await runVSCodeHook("PreToolUse", {
    ...localTool,
    timestamp: "2026-08-26T00:00:01Z",
  }, BASE_ENV, deps);
  await runVSCodeHook("PreToolUse", {
    ...localTool,
    tool_use_id: "tool-2",
  }, BASE_ENV, deps);

  const requestIds = calls
    .filter((call) => call.text)
    .map((call) => call.options.requestId);
  assert.equal(requestIds.length, 6);
  assert.equal(requestIds[0], requestIds[1], "same shared event and timestamp is stable");
  assert.notEqual(requestIds[1], requestIds[2], "different shared timestamps are distinct");
  assert.equal(requestIds[3], requestIds[4], "Local tool_use_id takes precedence over timestamp");
  assert.notEqual(requestIds[4], requestIds[5], "different Local tool_use_id values are distinct");
});

test("Local dispatch accepts optional common fields but rejects malformed mixed payloads", async () => {
  const calls: any[] = [];
  const deps = dependencies([{ prediction: "BENIGN", score: 0.01, threshold: 0.5 }], [], calls);
  const legacy: Record<string, unknown> = {
    hook_event_name: "UserPromptSubmit",
    timestamp: "2026-08-26T00:00:00Z",
    prompt: "legacy prompt without optional common fields",
  };
  assert.deepEqual(
    await dispatchVSCodeHook("userPromptSubmitted", legacy, BASE_ENV, deps),
    {},
  );
  assert.equal(calls.filter((call) => call.text).length, 1);

  const malformed = [
    { ...legacy, sessionId: "mixed-shared-session" },
    { ...legacy, timestamp: 1_788_307_200_000 },
    { ...legacy, hook_event_name: "PreToolUse" },
    {
      hook_event_name: "PreToolUse",
      timestamp: "2026-08-26T00:00:00Z",
      tool_name: "runTerminalCommand",
      tool_input: { command: "pwd" },
    },
    {
      ...copilotPayload("userPromptSubmitted"),
      hook_event_name: "UserPromptSubmit",
    },
    {
      ...copilotPayload("userPromptSubmitted"),
      session_id: "mixed-local-session",
    },
  ];
  for (const input of malformed) {
    assert.deepEqual(
      await dispatchVSCodeHook("userPromptSubmitted", input, BASE_ENV, deps),
      {},
    );
  }
  assert.deepEqual(
    await dispatchVSCodeHook("preToolUse", {
      hook_event_name: "PreToolUse",
      timestamp: "2026-08-26T00:00:00Z",
      tool_name: "runTerminalCommand",
      tool_input: { command: "pwd" },
    }, BASE_ENV, deps),
    {},
  );
  assert.equal(calls.filter((call) => call.text).length, 1);
});

test("numeric values in documented string fields fail open without classification or evidence", async () => {
  const calls: any[] = [];
  const events: any[] = [];
  const deps = dependencies([], events, calls);
  const malformed: Array<[VSCodeCopilotEventName, Record<string, unknown>]> = [
    ["userPromptSubmitted", { ...copilotPayload("userPromptSubmitted"), sessionId: 123 }],
    ["userPromptSubmitted", { ...copilotPayload("userPromptSubmitted"), cwd: 123 }],
    ["preToolUse", { ...copilotPayload("preToolUse"), toolName: 123 }],
    ["userPromptSubmitted", { ...payload("UserPromptSubmit"), session_id: 123 }],
    ["userPromptSubmitted", { ...payload("UserPromptSubmit"), cwd: 123 }],
    ["userPromptSubmitted", { ...payload("UserPromptSubmit"), transcript_path: 123 }],
    ["preToolUse", { ...payload("PreToolUse"), tool_name: 123 }],
    ["preToolUse", { ...payload("PreToolUse"), tool_use_id: 123 }],
  ];
  for (const [eventName, input] of malformed) {
    assert.deepEqual(await dispatchVSCodeHook(eventName, input, BASE_ENV, deps), {});
  }
  assert.equal(calls.length, 0);
  assert.equal(events.length, 0);
});

test("Copilot outputs use only documented event-specific controls", async () => {
  const blockEnv = { ...BASE_ENV, SILMARIL_MODE: "block" };
  const malicious = { prediction: "MALICIOUS", score: 0.99, threshold: 0.5 };
  const blockEvents: any[] = [];

  assert.deepEqual(
    await runVSCodeCopilotHook(
      "userPromptSubmitted",
      copilotPayload("userPromptSubmitted"),
      blockEnv,
      dependencies([malicious], blockEvents),
    ),
    {},
  );
  assert.deepEqual(
    await runVSCodeCopilotHook(
      "preToolUse",
      copilotPayload("preToolUse"),
      blockEnv,
      dependencies([{ prediction: "BENIGN", governance: { action: "block" } }], blockEvents),
    ),
    {
      permissionDecision: "deny",
      permissionDecisionReason: SAFE_BLOCK_MESSAGE,
    },
  );
  assert.deepEqual(
    await runVSCodeCopilotHook(
      "postToolUse",
      copilotPayload("postToolUse"),
      blockEnv,
      dependencies([malicious], blockEvents),
    ),
    {
      modifiedResult: {
        resultType: "success",
        textResultForLlm: SAFE_BLOCK_MESSAGE,
      },
    },
  );
  assert.equal(blockEvents[0].policyDecision, "unavailable");
  assert.equal(blockEvents[0].blockUnavailable, true);
  assert.equal(blockEvents[0].nativeAction, "allowed");
  assert.equal(blockEvents[1].policyDecision, "block");
  assert.equal(blockEvents[1].nativeAction, "block_returned");
  assert.equal(blockEvents[2].nativeAction, "content_replaced");
  assert.doesNotMatch(JSON.stringify(blockEvents), /user prompt|tool result|pwd/u);

  const warnEnv = { ...BASE_ENV, SILMARIL_MODE: "warn" };
  const warnEvents: any[] = [];
  assert.deepEqual(
    await runVSCodeCopilotHook(
      "userPromptSubmitted",
      copilotPayload("userPromptSubmitted"),
      warnEnv,
      dependencies([malicious], warnEvents),
    ),
    {},
  );
  assert.deepEqual(
    await runVSCodeCopilotHook(
      "preToolUse",
      copilotPayload("preToolUse"),
      warnEnv,
      dependencies([malicious], warnEvents),
    ),
    {},
  );
  assert.deepEqual(
    await runVSCodeCopilotHook(
      "postToolUse",
      copilotPayload("postToolUse"),
      warnEnv,
      dependencies([malicious], warnEvents),
    ),
    { additionalContext: SAFE_WARN_MESSAGE },
  );
  assert.deepEqual(
    warnEvents.map((event) => [event.warnDelivery, event.nativeAction]),
    [
      ["unsupported", "allowed"],
      ["unsupported", "allowed"],
      ["delivered", "warning_context_returned"],
    ],
  );
});

test("sessionStart only observes and never classifies in either schema", async () => {
  const calls: any[] = [];
  const observed: unknown[] = [];
  const deps = {
    ...dependencies([], [], calls),
    workspaceObserver: async (cwd: unknown) => { observed.push(cwd); },
  };
  assert.deepEqual(
    await dispatchVSCodeHook("sessionStart", payload("SessionStart"), BASE_ENV, deps),
    {},
  );
  assert.deepEqual(
    await dispatchVSCodeHook("sessionStart", copilotPayload("sessionStart"), BASE_ENV, deps),
    {},
  );
  assert.deepEqual(observed, ["/tmp/project", "/tmp/project"]);
  assert.equal(calls.filter((call) => call.text).length, 0);
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
    resource: { kind: "mcp_tool", id: "create_issue", parentId: "github" },
  });
  assert.deepEqual(withProvenance(
    { silmaril: { integration: "silmaril-vscode-firewall" } },
    undefined,
    governanceContext(toolTarget),
  ), {
    silmaril: {
      integration: "silmaril-vscode-firewall",
      provenance: {
        schema_version: 1,
        harness: "vscode",
      },
      governance: {
        agent: "vscode",
        resource: { kind: "mcp_tool", id: "create_issue", parent_id: "github" },
      },
    },
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

test("SDK 0.8.2 emits canonical agent, tool, and MCP resource wire shapes", async () => {
  const requests: Array<Record<string, any>> = [];
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    requests.push(JSON.parse(Buffer.concat(chunks).toString("utf8")));
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({
      prediction: "BENIGN",
      score: 0.01,
      threshold: 0.5,
    }));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const address = server.address();
    assert.ok(address && typeof address === "object");
    const env = {
      ...BASE_ENV,
      SILMARIL_API_URL: `http://127.0.0.1:${address.port}/classify`,
      SILMARIL_MODE: "shadow",
    };
    const deps: RuntimeDependencies = {
      firewallConstructor: Firewall as unknown as RuntimeDependencies["firewallConstructor"],
      evidenceEmitter: async () => undefined,
      workspaceObserver: async () => undefined,
      deviceName: () => undefined,
    };
    await runVSCodeHook("UserPromptSubmit", payload("UserPromptSubmit"), env, deps);
    await runVSCodeHook("PreToolUse", payload("PreToolUse"), env, deps);
    const mcpPayload = {
      ...payload("PreToolUse"),
      tool_name: "mcp__github__create_issue",
    };
    await runVSCodeHook("PreToolUse", mcpPayload, env, deps);
    await runVSCodeHook("PreToolUse", mcpPayload, env, deps);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }

  assert.equal(requests.length, 4);
  assert.deepEqual(requests.map((request) => request.resource), [
    { kind: "agent", id: "vscode" },
    { kind: "tool", id: "runTerminalCommand" },
    { kind: "mcp_tool", id: "create_issue", parent_id: "github" },
    { kind: "mcp_tool", id: "create_issue", parent_id: "github" },
  ]);
  const firstMcpRequest = requests[2];
  const secondMcpRequest = requests[3];
  assert.ok(firstMcpRequest && secondMcpRequest);
  assert.deepEqual(
    firstMcpRequest.metadata.silmaril.governance,
    {
      agent: "vscode",
      resource: { kind: "mcp_tool", id: "create_issue", parent_id: "github" },
    },
  );
  assert.equal(firstMcpRequest.metadata.silmaril.sdk_version, "0.8.2");
  assert.equal(firstMcpRequest.metadata.vscodeHookRuntime, "local");
  assert.equal(Object.hasOwn(firstMcpRequest.resource, "parentId"), false);
  assert.equal(
    Object.hasOwn(firstMcpRequest.metadata.silmaril.governance.resource, "parentId"),
    false,
  );
  assert.equal(
    firstMcpRequest.metadata.silmaril.request_id,
    secondMcpRequest.metadata.silmaril.request_id,
  );
  assert.doesNotMatch(JSON.stringify(requests), /"parentId"/u);
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
  assert.equal(packageJson.version, "0.3.0");
  assert.equal(pluginJson.$schema, "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json");
  assert.equal(pluginJson.name, "silmaril-vscode-firewall");
  assert.equal(pluginJson.version, packageJson.version);
  assert.equal(packageJson.dependencies["@silmaril-security/sdk"], "0.8.2");
  assert.equal(hooks.version, 1);
  assert.deepEqual(Object.keys(hooks.hooks), [
    "sessionStart",
    "userPromptSubmitted",
    "preToolUse",
    "postToolUse",
  ]);
  for (const [event, entries] of Object.entries(hooks.hooks) as Array<[string, any[]]>) {
    assert.equal(entries.length, 1);
    assert.equal(
      entries[0].command,
      `"${"${PLUGIN_ROOT}"}/scripts/run-hook.sh" dispatch ${event}`,
    );
    assert.equal(entries[0].timeoutSec, 12);
    assert.equal(entries[0].timeout, undefined);
  }
  assert.match(launcher, /stat -f '%u %Lp'/u);
  assert.match(launcher, /\[ -L "\$\{runtime_file\}" \]/u);
  assert.match(launcher, /\[ -L "\$\{node_path\}" \]/u);
  assert.match(launcher, /"\$@"/u);
});

test("private launcher safely handles plugin paths with spaces and both CLI forms", async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "silmaril launcher ")));
  const home = path.join(root, "home");
  const pluginPath = path.join(root, "plugin path with spaces");
  const repository = await realpath(new URL("../", import.meta.url));
  await mkdir(path.join(pluginPath, "dist"), { recursive: true });
  await copyFile(
    path.join(repository, "dist", "vscode-hook.js"),
    path.join(pluginPath, "dist", "vscode-hook.js"),
  );
  await mkdir(path.join(home, ".vscode"), { recursive: true });
  await writeFile(
    path.join(home, ".vscode", "silmaril-firewall-node-path"),
    `${process.execPath}\n`,
    { mode: 0o600 },
  );
  const launcher = path.join(repository, "scripts", "run-hook.sh");
  const env = { ...process.env, HOME: home, PLUGIN_ROOT: pluginPath };

  const dispatched = spawnSync(launcher, ["dispatch", "sessionStart"], {
    input: JSON.stringify(copilotPayload("sessionStart")),
    encoding: "utf8",
    env,
  });
  assert.equal(dispatched.status, 0, dispatched.stderr);
  assert.deepEqual(JSON.parse(dispatched.stdout), {});

  const legacy = spawnSync(launcher, ["SessionStart"], {
    input: JSON.stringify(payload("SessionStart")),
    encoding: "utf8",
    env,
  });
  assert.equal(legacy.status, 0, legacy.stderr);
  assert.deepEqual(JSON.parse(legacy.stdout), {});
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
