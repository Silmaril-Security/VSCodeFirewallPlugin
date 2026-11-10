import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readlink,
  realpath,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { createRequire } from "node:module";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  buildMinimalChildEnvironment,
  buildNativeLaunchArgs,
  buildNativeProfileSettings,
  byteReceipt,
  closeServer,
  collectStrings,
  createQualificationCoverage,
  createFreshQaLayout,
  inspectSecretStorageIsolation,
  inspectSecretStorageRuntimeLogs,
  inspectAndArchiveFreshUiFiles,
  inspectNativeCjsMissingIdentifiers,
  inspectNormalUiAgentEnablement,
  inspectProviderJournal,
  inspectSharedRouteSourceContracts,
  inspectSourceContracts,
  ownedProcessGroupExists,
  qualifyNativeVSCode,
  resolveNativeHandoffPaths,
  resolvePortableQaPolicy,
  restoreFreshProfileFiles,
  settleOwnedProcessGroup,
  startClassifier,
  startDestinationProxy,
  terminateOwnedProcessGroup,
  validateProviderJournalCapture,
  validateQaToolManifest,
  validateSharedCallbackRoutes,
  validateSharedExecutionRoute,
  waitForOwnedProcessGroup,
  writeFinalQualificationReceipt,
} from "../scripts/vscode-native-qualification.mjs";

const require = createRequire(import.meta.url);
const { workspaceTrustAction } = require(
  "../qa/vscode-native/extension/trust-policy.cjs",
) as {
  workspaceTrustAction(options: {
    workspaceTrusted: boolean;
    allowNormalTrustHandoff: boolean;
  }): string;
};
const { buildSafeExtensionInventory, MAX_EXTENSIONS } = require(
  "../qa/vscode-native/extension/inventory.cjs",
) as {
  MAX_EXTENSIONS: number;
  buildSafeExtensionInventory(extensions: unknown[]): Array<{
    id: string;
    version: string;
    extensionKind: string;
    isBuiltin: boolean;
    location: { scheme: string; basename: string };
    runningLocation: string;
  }>;
};
const {
  classificationAllowsNativePass,
  classifyFreshProfileUiFiles,
} = require(
  "../qa/vscode-native/extension/agent-ui-policy.cjs",
) as {
  classificationAllowsNativePass(
    classification: Record<string, unknown>,
  ): boolean;
  classifyFreshProfileUiFiles(options: Record<string, Uint8Array>): {
    expected: boolean;
    expectedUiTransitionObserved: boolean;
    phaseOrderValid: boolean;
    settings: { state: string };
    config: { state: string };
    workspace: { state: string };
  };
};
const {
  classifyNormalUiPhase,
  createLiveExtensionIdentityTracker,
  observeNormalUiPhase,
} = require(
  "../qa/vscode-native/extension/normal-ui-phase-observer.cjs",
) as {
  classifyNormalUiPhase(
    options: Record<string, unknown>,
  ): Record<string, any>;
  createLiveExtensionIdentityTracker(
    options: Record<string, unknown>,
  ): {
    observe(): Promise<Record<string, any>>;
    verifyCurrentAccepted(): Promise<Record<string, any>>;
  };
  observeNormalUiPhase(
    options: Record<string, unknown>,
  ): Promise<Record<string, any>>;
};
const { snapshotNativeState } = require(
  "../qa/vscode-native/extension/capture-state.cjs",
) as {
  snapshotNativeState(
    receipt: Record<string, any>,
    nativeState: Record<string, any> | undefined,
  ): Record<string, any>;
};
const {
  modelSelectorForRoute,
  modelSelectorFromPublicModel,
  parseChatTurnRows,
  readFreshProfileTurnRows,
  validateFirstSharedTurnRows,
  validateSelectionActionAttestation,
  validateWrappedModels,
} = require(
  "../qa/vscode-native/extension/shared-route-policy.cjs",
) as {
  modelSelectorForRoute(
    constants: { VENDOR: string; MODEL_ID: string },
    route: string,
  ): { vendor: string; id: string };
  modelSelectorFromPublicModel(
    model: { vendor: string; id: string },
  ): { vendor: string; id: string };
  parseChatTurnRows(
    logs: Array<{ relativePath: string; text: string }>,
  ): Array<Record<string, any>>;
  readFreshProfileTurnRows(
    userData: string,
  ): Promise<Array<Record<string, any>>>;
  validateFirstSharedTurnRows(
    rows: Array<Record<string, any>>,
  ): Record<string, any>;
  validateSelectionActionAttestation(
    value: Record<string, any>,
    expectedModel: { vendor: string; id: string },
  ): Record<string, any>;
  validateWrappedModels(
    models: Array<Record<string, any>>,
    constants: { VENDOR: string; MODEL_ID: string },
  ): {
    source: string;
    name: string;
    vendor: string;
    id: string;
    family: string;
    version: string;
    maxInputTokens: number;
  };
};
const {
  createProviderJournal,
  parseProviderJournalBytes,
} = require(
  "../qa/vscode-native/extension/provider-journal.cjs",
) as {
  createProviderJournal(filePath: string): Promise<{
    append(record: Record<string, any>): Promise<Record<string, any>>;
    flush(): Promise<void>;
    close(): Promise<void>;
  }>;
  parseProviderJournalBytes(value: Uint8Array): {
    integrity: "pass" | "fail";
    validRecordCount: number;
    records: Array<Record<string, any>>;
    errors: Array<{ line: number; message: string }>;
    partialTrailingLine?: {
      byteLength: number;
      sha256: string;
      base64: string;
    };
  };
};

test("native qualification records exact transformed bytes", () => {
  const value = " \ttransformed\r\nprompt β\u0000 ";
  assert.equal(byteReceipt(value).byteLength, Buffer.byteLength(value, "utf8"));
  assert.equal(
    byteReceipt(value).utf8Hex,
    Buffer.from(value, "utf8").toString("hex"),
  );
  assert.notEqual(byteReceipt(value).sha256, byteReceipt(value.trim()).sha256);
});

test("native qualification finds poison in nested provider messages", () => {
  const nested = {
    messages: [{
      content: [{
        type: "toolResult",
        content: [{ type: "text", value: "SYNTHETIC_POISON" }],
      }],
    }],
  };
  assert.ok(collectStrings(nested).includes("SYNTHETIC_POISON"));
});

test("provider journal is exclusive, ordered, durable, and retains title requests", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svqa-journal-"));
  try {
    const journalPath = path.join(temporary, "provider-tool.ndjson");
    const journal = await createProviderJournal(journalPath);
    const titleRequest = {
      sequence: 1,
      messages: [{
        role: "user",
        content: [{ type: "text", value: "title request synthetic prompt" }],
      }],
      tools: [],
    };
    await Promise.all([
      journal.append({
        type: "provider-request",
        providerSequence: 1,
        request: titleRequest,
      }),
      journal.append({
        type: "tool-invocation",
        toolName: "silmaril_native_qa_posttool_8d724ae7",
        invocationCount: 1,
      }),
    ]);
    await journal.close();

    const info = await lstat(journalPath);
    assert.equal(info.isFile(), true);
    assert.equal(info.mode & 0o777, 0o600);
    const inspected = await inspectProviderJournal(journalPath);
    assert.equal(inspected.integrity, "pass");
    assert.equal(inspected.validRecordCount, 2);
    assert.deepEqual(
      inspected.records.map((record) => record.journalSequence),
      [1, 2],
    );
    assert.equal(
      collectStrings(inspected.records).includes("title request synthetic prompt"),
      true,
      "Title-like provider requests must not be filtered from the journal",
    );
    assert.deepEqual(
      validateProviderJournalCapture(inspected, {
        providerRequests: [titleRequest],
        toolInvocations: {
          silmaril_native_qa_preblock_8d724ae7: 0,
          silmaril_native_qa_posttool_8d724ae7: 1,
        },
      }),
      {
        result: "pass",
        providerRequestCount: 1,
        toolInvocations: {
          silmaril_native_qa_preblock_8d724ae7: 0,
          silmaril_native_qa_posttool_8d724ae7: 1,
        },
      },
    );
    await assert.rejects(
      createProviderJournal(journalPath),
      (error: NodeJS.ErrnoException) => error.code === "EEXIST",
    );

    const externalPath = path.join(temporary, "external.ndjson");
    const symlinkPath = path.join(temporary, "journal-link.ndjson");
    await writeFile(externalPath, "external\n", { mode: 0o600 });
    await symlink(externalPath, symlinkPath);
    await assert.rejects(
      createProviderJournal(symlinkPath),
      (error: NodeJS.ErrnoException) =>
        error.code === "EEXIST" || error.code === "ELOOP",
    );
    assert.equal(await readFile(externalPath, "utf8"), "external\n");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("provider journal preserves complete rows and fails a torn trailing row", () => {
  const complete = Buffer.from(`${JSON.stringify({
    type: "provider-request",
    providerSequence: 1,
    request: { sequence: 1, messages: [] },
    schemaVersion: 1,
    journalSequence: 1,
    state: "in-progress",
    completion: "not-finished",
  })}\n`, "utf8");
  const torn = Buffer.from('{"type":"tool-invocation"', "utf8");
  const parsed = parseProviderJournalBytes(Buffer.concat([complete, torn]));
  assert.equal(parsed.integrity, "fail");
  assert.equal(parsed.validRecordCount, 1);
  assert.equal(parsed.records[0]?.type, "provider-request");
  assert.equal(parsed.partialTrailingLine?.byteLength, torn.byteLength);
  assert.equal(
    Buffer.from(parsed.partialTrailingLine?.base64 ?? "", "base64").equals(torn),
    true,
  );
  const splitUtf8 = Buffer.from([0x7b, 0x22, 0xce]);
  const split = parseProviderJournalBytes(Buffer.concat([complete, splitUtf8]));
  assert.equal(split.integrity, "fail");
  assert.equal(split.validRecordCount, 1);
  assert.deepEqual(
    Buffer.from(split.partialTrailingLine!.base64, "base64"),
    splitUtf8,
    "A torn multibyte character must retain its original bytes",
  );
  const invalidUtf8 = Buffer.from(complete);
  invalidUtf8[invalidUtf8.indexOf(Buffer.from("provider-request"))] = 0xff;
  assert.equal(parseProviderJournalBytes(invalidUtf8).integrity, "fail");
});

test("QA extension durably journals observations before progress or tool effects", async () => {
  const extensionSource = await readFile(new URL(
    "../qa/vscode-native/extension/extension.cjs",
    import.meta.url,
  ), "utf8");
  assert.match(
    extensionSource,
    /state\.providerRequests\.push\(providerRequest\);\s+await journal\.append\(\{[\s\S]*type: "provider-request"[\s\S]*\}\);\s+\n\s+if \(tool/u,
  );
  assert.match(
    extensionSource,
    /state\.toolInvocations\[PRE_TOOL\] \+= 1;\s+await journal\.append\(\{[\s\S]*toolName: PRE_TOOL[\s\S]*\}\);\s+const markerPath/u,
  );
  assert.match(
    extensionSource,
    /state\.toolInvocations\[POST_TOOL\] \+= 1;\s+await journal\.append\(\{[\s\S]*toolName: POST_TOOL[\s\S]*\}\);\s+return new vscode\.LanguageModelToolResult/u,
  );
});

type SharedRouteRow = {
  body: {
    hook: string;
    text: string;
    metadata?: {
      vscodeHookRuntime: string;
      vscodeHookEvent: string;
    };
  };
};

function sharedRouteRows(): SharedRouteRow[] {
  const row = (
    hook: string,
    marker: string,
    event: string,
  ): SharedRouteRow => ({
    body: {
      hook,
      text: marker,
      metadata: {
        vscodeHookRuntime: "copilot",
        vscodeHookEvent: event,
      },
    },
  });
  return [
    row(
      "user_input",
      "SILMARIL_NATIVE_ALLOW_8d724ae7",
      "userPromptTransformed",
    ),
    row(
      "user_input",
      "SILMARIL_NATIVE_BLOCK_8d724ae7",
      "userPromptTransformed",
    ),
    row(
      "user_input",
      "SILMARIL_NATIVE_PREBLOCK_8d724ae7",
      "userPromptTransformed",
    ),
    row(
      "user_input",
      "SILMARIL_NATIVE_POSTTOOL_8d724ae7",
      "userPromptTransformed",
    ),
    row(
      "tool_call",
      "SILMARIL_NATIVE_PREBLOCK_8d724ae7",
      "preToolUse",
    ),
    row(
      "tool_response",
      "SILMARIL_NATIVE_POISON_8d724ae7",
      "postToolUse",
    ),
  ];
}

test("native core route accepts only exact shared callback metadata", () => {
  assert.deepEqual(validateSharedCallbackRoutes(sharedRouteRows()), {
    result: "verified",
    runtime: "copilot",
    callbacks: {
      userPromptTransformed: 4,
      preToolUse: 1,
      postToolUse: 1,
    },
  });

  const localRows = sharedRouteRows();
  for (const request of localRows) {
    request.body.metadata!.vscodeHookRuntime = "local";
  }
  assert.throws(
    () => validateSharedCallbackRoutes(localRows),
    /must use vscodeHookRuntime=copilot/u,
  );

  const missingMetadata = sharedRouteRows();
  delete missingMetadata[0]!.body.metadata;
  assert.throws(
    () => validateSharedCallbackRoutes(missingMetadata),
    /must use vscodeHookRuntime=copilot/u,
  );

  const mixedRoutes = sharedRouteRows();
  mixedRoutes[2]!.body.metadata!.vscodeHookRuntime = "local";
  assert.throws(
    () => validateSharedCallbackRoutes(mixedRoutes),
    /must use vscodeHookRuntime=copilot/u,
  );

  const wrongEvent = sharedRouteRows();
  wrongEvent[3]!.body.metadata!.vscodeHookEvent = "userPromptSubmitted";
  assert.throws(
    () => validateSharedCallbackRoutes(wrongEvent),
    /must use vscodeHookEvent=userPromptTransformed/u,
  );
  const wrongPreToolEvent = sharedRouteRows();
  wrongPreToolEvent[4]!.body.metadata!.vscodeHookEvent = "postToolUse";
  assert.throws(
    () => validateSharedCallbackRoutes(wrongPreToolEvent),
    /must use vscodeHookEvent=preToolUse/u,
  );
  const wrongPostToolEvent = sharedRouteRows();
  wrongPostToolEvent[5]!.body.metadata!.vscodeHookEvent = "preToolUse";
  assert.throws(
    () => validateSharedCallbackRoutes(wrongPostToolEvent),
    /must use vscodeHookEvent=postToolUse/u,
  );

  const duplicateCallback = sharedRouteRows();
  duplicateCallback.push(structuredClone(duplicateCallback[0]!));
  assert.throws(
    () => validateSharedCallbackRoutes(duplicateCallback),
    /Expected exactly one user_input callback/u,
  );
  const extraLocalCallback = sharedRouteRows();
  extraLocalCallback.push({ body: {
    hook: "tool_call",
    text: "SILMARIL_NATIVE_POSTTOOL_8d724ae7",
    metadata: { vscodeHookRuntime: "local", vscodeHookEvent: "PreToolUse" },
  } });
  assert.throws(
    () => validateSharedCallbackRoutes(extraLocalCallback),
    /must use vscodeHookRuntime=copilot/u,
  );
});

test("shared execution requires wrapped selector, shared resources, and strict callbacks", () => {
  const callbackProof = validateSharedCallbackRoutes(sharedRouteRows());
  const modelId =
    "silmaril-native-qa-dummy-8d724ae7/silmaril-native-qa-local-deterministic-8d724ae7";
  const capture = {
    sessionRoute: {
      modelSelector: {
        vendor: "agent-host-copilotcli",
        id: modelId,
      },
      publicWrappedModel: {
        vendor: "agent-host-copilotcli",
        id: modelId,
      },
      selectionAttestation: {
        executionProof: false,
      },
      firstTurnEvidence: {
        source: "fresh-profile-renderer-logs",
        firstTurn: {
          sessionType: "agent-host-copilotcli",
        },
      },
    },
    providerRequests: Array.from({ length: 4 }, () => ({
      model: { id: "silmaril-native-qa-local-deterministic-8d724ae7" },
    })),
  };
  const turn = (index: number, sessionType = "agent-host-copilotcli") =>
    `[ChatTTFP] end ${JSON.stringify({
      interactionKind: "turn",
      chatSessionId: `shared-${index}`,
      sessionType,
      agent: "copilotcli",
      model: modelId,
    })}`;
  const combinedLogs = [
    "startup empty session resource = vscode-chat-session://local/empty-startup",
    "current session resource = vscode-chat-session://agent-host-copilotcli/shared-1",
    ...Array.from({ length: 4 }, (_, index) => turn(index)),
  ].join("\n");
  const proof = validateSharedExecutionRoute({
    sessionRoute: "shared-copilot",
    combinedLogs,
    callbackProof,
    capture,
  });
  assert.equal(proof.execution, "verified");
  assert.equal(proof.sessionType, "agent-host-copilotcli");
  assert.equal(proof.selectionAttestationIsExecutionProof, false);
  assert.equal(proof.firstTurnCheckpointObserved, true);

  assert.throws(
    () => validateSharedExecutionRoute({
      sessionRoute: "legacy-local",
      combinedLogs,
      callbackProof,
      capture,
    }),
    /Legacy Local configuration cannot satisfy/u,
  );
  assert.throws(
    () => validateSharedExecutionRoute({
      sessionRoute: "shared-copilot",
      combinedLogs: `${combinedLogs}\n${turn(5, "local")}`,
      callbackProof,
      capture,
    }),
    /Mixed or Local/u,
  );
});

test("first safe allow turn stops missing, Local, or mixed routes before later queries", async () => {
  const row = (
    sessionType: string,
    epochMs: number,
    chatSessionId: string,
  ) => `[ChatTTFP] end ${JSON.stringify({
    interactionKind: "turn",
    sessionType,
    epochMs,
    chatSessionId,
    agent: "copilotcli",
    model: "synthetic-unit-contract",
  })}`;
  assert.throws(
    () => validateFirstSharedTurnRows([]),
    /Missing first-turn/u,
  );
  const local = parseChatTurnRows([{
    relativePath: "window1/renderer.log",
    text: row("local", 1, "local-first"),
  }]);
  assert.throws(
    () => validateFirstSharedTurnRows(local),
    /First safe allow turn did not execute/u,
  );
  const mixed = parseChatTurnRows([{
    relativePath: "window1/renderer.log",
    text: [
      row("agent-host-copilotcli", 1, "shared-first"),
      row("local", 2, "local-second"),
    ].join("\n"),
  }]);
  assert.throws(
    () => validateFirstSharedTurnRows(mixed),
    /Local or mixed/u,
  );
  const shared = validateFirstSharedTurnRows(parseChatTurnRows([{
    relativePath: "window1/renderer.log",
    text: row("agent-host-copilotcli", 1, "shared-first"),
  }]));
  assert.equal(shared.firstTurn.sessionType, "agent-host-copilotcli");
  assert.equal(shared.observedTurnCount, 1);

  const suite = await readFile(new URL(
    "../qa/vscode-native/extension/suite.cjs",
    import.meta.url,
  ), "utf8");
  assert.match(
    suite,
    /for \(const \[index, input\] of turnInputs\.entries\(\)\) \{[\s\S]*?await runTurn\(modelSelector, input\.query, input\.tools\);[\s\S]*?if \(sessionRoute === SHARED_COPILOT_ROUTE && index === 0\) \{[\s\S]*?await waitForFirstSharedTurnEvidence\(\);[\s\S]*?\}\s+\}/u,
    "First-turn route gate must run in the first iteration before the next query",
  );
  assert.doesNotMatch(
    suite,
    /if \(index === 0\) \{\s+receipt\.sessionRoute\.firstTurnEvidence/u,
    "Legacy Local must never invoke the shared first-turn guard",
  );
});

test("fresh-profile first-turn reader skips symlinked logs", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svqa-first-turn-"));
  try {
    const userData = path.join(temporary, "user-data");
    const rendererDirectory = path.join(userData, "logs", "fresh", "window1");
    const outside = path.join(temporary, "outside");
    await mkdir(rendererDirectory, { recursive: true });
    await mkdir(outside);
    const makeRow = (sessionType: string) =>
      `[ChatTTFP] end ${JSON.stringify({
        interactionKind: "turn",
        sessionType,
        epochMs: sessionType === "agent-host-copilotcli" ? 1 : 0,
        chatSessionId: sessionType,
      })}\n`;
    await writeFile(
      path.join(rendererDirectory, "renderer.log"),
      makeRow("agent-host-copilotcli"),
    );
    await writeFile(
      path.join(outside, "renderer.log"),
      makeRow("local"),
    );
    await symlink(
      outside,
      path.join(userData, "logs", "fresh", "escaped-logs"),
    );
    await symlink(
      path.join(outside, "renderer.log"),
      path.join(rendererDirectory, "linked.log"),
    );
    const rows = await readFreshProfileTurnRows(await realpath(userData));
    assert.equal(rows.length, 1);
    assert.equal(rows[0]!.sessionType, "agent-host-copilotcli");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("qualification coverage never equates the four-case core with release qualification", async () => {
  const coverage = createQualificationCoverage();
  assert.deepEqual(coverage, {
    nativeCore: {
      scope: "four-case-only",
      caseCount: 4,
      result: "not-run",
    },
    releaseQualification: {
      result: "incomplete",
      qualifiedForPublication: false,
    },
    batchResume: {
      result: "unsupported",
    },
    nativeWarnShadow: {
      result: "unassessed",
    },
    sharedRoute: {
      result: "unverified",
    },
  });

  coverage.sharedRoute = validateSharedCallbackRoutes(sharedRouteRows());
  coverage.nativeCore.result = "pass";
  assert.equal(coverage.sharedRoute.result, "verified");
  assert.equal(coverage.releaseQualification.result, "incomplete");
  assert.equal(coverage.releaseQualification.qualifiedForPublication, false);

  const launcher = await readFile(new URL(
    "../scripts/vscode-native-qualification.mjs",
    import.meta.url,
  ), "utf8");
  assert.match(launcher, /resultScope: "source-preflight"/u);
  const preflightReturn = launcher.indexOf("if (!policy.allowLaunch)");
  const nativeScope = launcher.indexOf(
    "receipt.resultScope = policy.sessionRoute",
  );
  const nativeCoreStart = launcher.indexOf(
    'receipt.coverage.nativeCore.result = "fail"',
    nativeScope,
  );
  assert.ok(
    preflightReturn > 0
      && preflightReturn < nativeScope
      && nativeScope < nativeCoreStart,
    "Preflight must return before native-core or shared-route validation",
  );

  const temporary = await mkdtemp(path.join(os.tmpdir(), "svqa-coverage-"));
  try {
    const sourceReceipt = {
      qualification: "unit-contract-only",
      result: "source-pass",
      process: {},
      coverage: createQualificationCoverage(),
    };
    await writeFinalQualificationReceipt({
      receiptPath: path.join(temporary, "source.json"),
      receipt: sourceReceipt,
      ownedServersClosed: true,
      ownedProcessSettled: true,
    });
    assert.equal(sourceReceipt.coverage.sharedRoute.result, "unverified");
    assert.equal(
      sourceReceipt.coverage.releaseQualification.result,
      "incomplete",
    );

    const nativeCoreReceipt = {
      qualification: "unit-contract-only",
      result: "pass",
      process: { pid: 42, code: 0 },
      coverage,
    };
    await writeFinalQualificationReceipt({
      receiptPath: path.join(temporary, "native-core.json"),
      receipt: nativeCoreReceipt,
      ownedServersClosed: true,
      ownedProcessSettled: true,
    });
    assert.equal(nativeCoreReceipt.coverage.nativeCore.result, "pass");
    assert.equal(
      nativeCoreReceipt.coverage.releaseQualification.result,
      "incomplete",
    );
    const cleanupFailure = structuredClone(nativeCoreReceipt);
    await assert.rejects(
      writeFinalQualificationReceipt({
        receiptPath: path.join(temporary, "cleanup-failure.json"),
        receipt: cleanupFailure,
        ownedServersClosed: false,
        ownedProcessSettled: true,
      }),
      /loopback servers failed to close/u,
    );
    assert.equal(cleanupFailure.result, "fail");
    assert.equal(cleanupFailure.coverage.nativeCore.result, "fail");

    const failedReceipt = {
      qualification: "unit-contract-only",
      result: "fail",
      process: { pid: 42, code: 1 },
      coverage: createQualificationCoverage(),
    };
    await assert.rejects(
      writeFinalQualificationReceipt({
        receiptPath: path.join(temporary, "failure.json"),
        receipt: failedReceipt,
        failure: new Error("synthetic unit-contract failure"),
        ownedServersClosed: true,
        ownedProcessSettled: true,
      }),
      /synthetic unit-contract failure/u,
    );
    assert.equal(failedReceipt.coverage.sharedRoute.result, "unverified");
    assert.equal(
      failedReceipt.coverage.releaseQualification.result,
      "incomplete",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("source preflight requires the transformed hook mapping and mutation", () => {
  const common = {
    api: [
      "interface LanguageModelChatProvider",
      "registerLanguageModelChatProvider",
      "languageModelChatProviders",
    ].join(" "),
    copilot: [
      'IS_SCENARIO_AUTOMATION==="1"',
      "ScenarioAutomation: using BYOK model",
      "lm.selectChatModels()",
      "tokenNoAuthURL",
    ].join(" "),
    workbench: [
      '"workbench.action.chat.open"',
      '"chat.pluginLocations"',
      "ConfiguredAgentPluginDiscovery",
      "modelSelector",
      "toolsInclude",
      "blockOnResponse",
    ].join(" "),
  };
  const floor = inspectSourceContracts({
    ...common,
    agentHost: [
      'preToolUse:"PreToolUse"',
      "onPreToolUse",
      "permissionDecision",
      'postToolUse:"PostToolUse"',
      "onPostToolUse",
    ].join(" "),
  });
  assert.equal(floor.transformedHook, false);
  assert.equal(floor.preToolHook, true);
  assert.equal(floor.postToolHook, false);

  const current = inspectSourceContracts({
    ...common,
    agentHost: [
      'userPromptTransformed:"UserPromptTransformed"',
      "onUserPromptTransformed",
      "modifiedTransformedPrompt",
      'preToolUse:"PreToolUse"',
      "onPreToolUse",
      "permissionDecision",
      'postToolUse:"PostToolUse"',
      "onPostToolUse",
      "modifiedResult",
    ].join(" "),
  });
  assert.equal(current.transformedHook, true);
});

test("shared source guard distinguishes telemetry from visible session routing", () => {
  const workbench = [
    "a?.targetChatSessionType?Mk(a.targetChatSessionType,i):void 0",
    "byokModelIdentifier",
    'function FDo(s,o,e,t){return o&&o!=="local"&&dXe(s,o)?s.filter(i=>i.metadata?.targetChatSessionType===o',
    "s.filter(i=>!i.metadata?.targetChatSessionType",
    "function Fvi(s,o,e){let t=s.get(fi),i=o.viewModel?.model.sessionResource,n=i?ui(i):void 0,r=EEt(s,{explicitOverride:e,currentSessionType:n})",
    "n?.currentSessionType&&Vci(n.currentSessionType",
    "function EEt(s,o)",
    "return qDe(e,t,i,n,a,o,c",
    'id:pf,title:F(13116,"New Chat")',
  ].join(" ");
  const agentHost = [
    "this._wrapper.session.send({prompt:",
    "_pendingClientToolCalls.respondOrBuffer",
    'type:"chat/toolCallStart"',
    "onUserPromptTransformed",
    "toolResult:{...p.toolResult,...g.modifiedResult}",
    "enum:[...Cx],enumDescriptions:[m(2794,null),m(2792,null),m(2793,null)]",
    'default:Do.quality!=="stable"?"activeAgent":"utility",scope:1',
    'o=>o==="activeAgent"',
    'o=>o==="agentReview"',
    "getAutomaticTitleGenerationStrategy",
    "_unpersistedTitleStrategies",
    'type:"openai",wireApi:"responses",baseUrl:s.providerBaseUrl(l)',
    'r.listen(0,"127.0.0.1"',
    "http://127.0.0.1:",
    "this._bridgeRegistry.getServingConnection()",
    '_writeJsonError(t,503,"No renderer connection available to service BYOK models"',
    "let I=await y.chat(h)",
    "resolveByokSessionConfig",
    "_byokLmBridgeRegistry",
    "_byokLmProxyService.start",
  ].join(" ");
  assert.deepEqual(
    inspectSharedRouteSourceContracts({ workbench, agentHost }),
    {
      targetChatSessionTypeTelemetry: true,
      wrappedModelSessionTypeFiltering: true,
      visibleNewChatCurrentSessionForwarding: true,
      visibleNewChatAction: true,
      copilotSdkSend: true,
      clientToolBridge: true,
      hookConverters: true,
      titleGenerationDeclaration: true,
      titleGenerationNewSessionLogic: true,
      byokProviderLoopbackConfiguration: true,
      byokLocalhostBinding: true,
      byokRendererRequired: true,
      byokRegistryChatBridge: true,
    },
  );
  assert.equal(
    inspectSharedRouteSourceContracts({
      workbench: workbench.replace(
        "targetChatSessionType?Mk",
        "targetChatSessionType?MUTATED",
      ),
      agentHost,
    }).targetChatSessionTypeTelemetry,
    false,
  );
  assert.equal(
    inspectSharedRouteSourceContracts({
      workbench: workbench.replace("function FDo", "function MUTATED"),
      agentHost,
    }).wrappedModelSessionTypeFiltering,
    false,
  );
  assert.equal(
    inspectSharedRouteSourceContracts({
      workbench: workbench.replace(
        "currentSessionType:n",
        "currentSessionType:MUTATED",
      ),
      agentHost,
    }).visibleNewChatCurrentSessionForwarding,
    false,
  );
  assert.equal(
    inspectSharedRouteSourceContracts({
      workbench: workbench.replace("return qDe", "return MUTATED"),
      agentHost,
    }).visibleNewChatCurrentSessionForwarding,
    false,
  );
  assert.equal(
    inspectSharedRouteSourceContracts({
      workbench: workbench.replace('"New Chat"', '"MUTATED"'),
      agentHost,
    }).visibleNewChatAction,
    false,
  );
  for (const [needle, contract] of [
    [
      'type:"openai",wireApi:"responses",baseUrl:s.providerBaseUrl(l)',
      "byokProviderLoopbackConfiguration",
    ],
    ['r.listen(0,"127.0.0.1"', "byokLocalhostBinding"],
    [
      "No renderer connection available to service BYOK models",
      "byokRendererRequired",
    ],
    ["let I=await y.chat(h)", "byokRegistryChatBridge"],
  ] as const) {
    const mutated = inspectSharedRouteSourceContracts({
      workbench,
      agentHost: agentHost.replace(needle, "MUTATED"),
    });
    assert.equal(
      mutated[contract],
      false,
      `${contract} must fail when its signed source prefix changes`,
    );
  }
});

test("native launch requires ephemeral in-memory secret storage", () => {
  const args = buildNativeLaunchArgs({
    workspaceFile: "/private/native.code-workspace",
    userData: "/private/user-data",
    extensions: "/private/extensions",
    proxyUrl: "http://127.0.0.1:12345",
  });
  assert.ok(args.includes("--use-inmemory-secretstorage"));
  assert.equal(
    args.filter((value) =>
      value.startsWith("--extensionDevelopmentPath=")).length,
    1,
    "Only the QA provider extension may use development registration",
  );
  assert.equal(args.some((value) => value.startsWith("--password-store")), false);
  assert.equal(args.includes("--disable-workspace-trust"), false);
  assert.equal(args.includes("--no-sandbox"), false);
});

test("secret-storage source proof spans main, shared, extension host, and GitHub auth", () => {
  const contracts = inspectSecretStorageIsolation({
    main: [
      '"use-inmemory-secretstorage":{type:"boolean"',
      'get useInMemorySecretStorage(){return!!this.args["use-inmemory-secretstorage"]}',
    ].join(" "),
    shared: [
      "this.configuration.args",
      'get useInMemorySecretStorage(){return!!this.args["use-inmemory-secretstorage"]}',
    ].join(" "),
    workbench: [
      "super(!!r.useInMemorySecretStorage",
      "if(!this._useInMemoryStorage&&await this._encryptionService.isEncryptionAvailable())",
      'this._type="in-memory"',
    ].join(" "),
    extensionHost: [
      "getProxy(H.MainThreadSecretState)",
      "$getPassword",
      "$setPassword",
    ].join(" "),
    githubAuth: [
      "this.context.secrets.get(this.serviceId)",
      "this.context.secrets.store(this.serviceId",
      "this.context.secrets.delete(this.serviceId)",
      "Reading sessions from keychain...",
    ].join(" "),
  });
  assert.deepEqual(Object.values(contracts), [true, true, true, true, true]);
});

test("runtime isolation requires selected flag and in-memory service without OS probe", () => {
  assert.deepEqual(inspectSecretStorageRuntimeLogs({
    mainLog: '"use-inmemory-secretstorage":true',
    combinedLogs:
      "[SecretStorageService] Encryption is not available, falling back to in-memory storage",
  }), {
    launchFlagSelected: true,
    inMemoryServiceSelected: true,
    osEncryptionProbeObserved: false,
  });
  assert.equal(inspectSecretStorageRuntimeLogs({
    mainLog: '"use-inmemory-secretstorage":false',
    combinedLogs:
      "[EncryptionMainService] Checking if encryption is available",
  }).osEncryptionProbeObserved, true);
});

test("signed source proves the account-free two-phase normal Extensions UI lifecycle", () => {
  const contracts = inspectNormalUiAgentEnablement({
    workbench: [
      'super("extensions.enable",dc.LABEL_ACTION_CLASS',
      'static{this.ID="extensions.enableForWorkspace"}',
      "defaultChatAgent?.chatExtensionId))return",
      'static{this.ID="extensions.enableGlobally"}',
      "defaultChatAgent?.chatExtensionId))return",
      'static{this.ID="extensions.disableForWorkspace"}',
      'static{this.ID="extensions.enableAIGlobally"}',
      "this.enabled=e.value===!0",
      "this.configurationService.updateValue(mc,!1)",
      'static{this.ID="extensions.enableAIInWorkspace"}',
      "if(e.value!==!1)",
      "setEnablement(this.extension,13)",
      "this.configurationService.updateValue(mc,!1,5)",
      'static{this.ID="extensions.disableAIGlobally"}',
      "this.configurationService.getValue(mc)!==!0",
      "this.configurationService.updateValue(mc,!0)",
      'static{this.ID="extensions.disableAIInWorkspace"}',
      "ensureChatExtensionInitialDisabledState(){",
      "Disabling builtin chat extension as chat set up is not completed",
      "this._disableExtension({id:this._chatExtensionId})",
      "}get hasWorkspace(){",
      "this._extensionEnablementService.onEnablementChanged",
      "AbstractExtensionService.onEnablementChanged fired",
      "this._handleDeltaExtensions",
      "this._onDidChangeExtensions.fire({added:r,removed:n})",
    ].join(" "),
    nlsMessages: [
      "Disable AI Features",
      "Enable AI Features (Workspace)",
      "Enable AI features in this workspace",
    ],
  });
  assert.deepEqual(Object.values(contracts), new Array(9).fill(true));
  assert.equal(inspectNormalUiAgentEnablement({
    workbench: [
      'super("extensions.enable",dc.LABEL_ACTION_CLASS',
      'static{this.ID="extensions.enableForWorkspace"}',
      "defaultChatAgent?.chatExtensionId))return",
      'static{this.ID="extensions.enableGlobally"}',
      "defaultChatAgent?.chatExtensionId))return",
      'static{this.ID="extensions.disableForWorkspace"}',
      'static{this.ID="extensions.enableAIGlobally"}',
      "this.enabled=e.value===!0",
      "this.configurationService.updateValue(mc,!1)",
      'static{this.ID="extensions.enableAIInWorkspace"}',
      "if(e.value!==!1)",
      "setEnablement(this.extension,13)",
      "this.configurationService.updateValue(mc,!1,5)",
      'static{this.ID="extensions.disableAIGlobally"}',
      "this.configurationService.getValue(mc)!==!0",
      "this.configurationService.updateValue(mc,!0)",
      "signIn()",
      'static{this.ID="extensions.disableAIInWorkspace"}',
      "ensureChatExtensionInitialDisabledState(){",
      "Disabling builtin chat extension as chat set up is not completed",
      "this._disableExtension({id:this._chatExtensionId})",
      "}get hasWorkspace(){",
      "this._extensionEnablementService.onEnablementChanged",
      "AbstractExtensionService.onEnablementChanged fired",
      "this._handleDeltaExtensions",
      "this._onDidChangeExtensions.fire({added:r,removed:n})",
    ].join(" "),
    nlsMessages: [
      "Disable AI Features",
      "Enable AI Features (Workspace)",
      "Enable AI features in this workspace",
    ],
  }).noAccountInstallOrTermsInActions, false);
});

test("native suite uses the normalized signed built-in Copilot identifier", async () => {
  const suite = await readFile(new URL(
    "../qa/vscode-native/extension/suite.cjs",
    import.meta.url,
  ), "utf8");
  assert.match(
    suite,
    /vscode\.extensions\.getExtension\("github\.copilot-chat"\)/u,
  );
  assert.doesNotMatch(suite, /getExtension\("GitHub\.copilot-chat"\)/u);
  assert.match(suite, /SILMARIL_NATIVE_EXISTING_LOG_DIRECTORIES/u);
  assert.ok(
    suite.indexOf("buildSafeExtensionInventory(vscode.extensions.all)")
      < suite.indexOf('getExtension("github.copilot-chat")'),
    "Safe extension inventory must be captured before the Copilot assertion",
  );
  assert.match(suite, /SILMARIL_NATIVE_ALLOW_UI_ENABLE_HANDOFF === "1"/u);
  assert.match(suite, /vscode\.workspace\.onDidChangeConfiguration/u);
  assert.match(suite, /vscode\.extensions\.onDidChange/u);
  assert.match(suite, /180_000/u);
  assert.match(suite, /10_000/u);
  assert.match(suite, /NORMAL_UI_POLL_INTERVAL_MS = 100/u);
  assert.match(suite, /observeNormalUiPhase/u);
  assert.match(suite, /createLiveExtensionIdentityTracker/u);
  assert.match(suite, /extensionIdentity\.verifyCurrentAccepted\(\)/u);
  assert.match(suite, /canonicalPath/u);
  assert.match(suite, /identity,/u);
  assert.match(suite, /normal-ui-disable-ai-required/u);
  assert.match(suite, /normal-ui-workspace-ai-enable-required/u);
  assert.match(suite, /writeImmutableCapture/u);
  assert.match(suite, /verifyOrdinaryBuiltInCopilot/u);
  assert.doesNotMatch(
    suite,
    /executeCommand\(["']extensions\.enable/u,
    "The worker must not invoke an extension-enable command",
  );
});

test("native launcher keeps reviewed cumulative handoff and process deadlines", async () => {
  const source = await readFile(new URL(
    "../scripts/vscode-native-qualification.mjs",
    import.meta.url,
  ), "utf8");
  assert.match(source, /AI_DISABLE_READY_TIMEOUT_MS = 225_000/u);
  assert.match(source, /WORKSPACE_AI_ENABLE_READY_TIMEOUT_MS = 420_000/u);
  assert.match(source, /UI_HANDOFF_PROCESS_TIMEOUT_MS = 600_000/u);
  assert.match(
    source,
    /timeOrigin: "owned-vscode-process-spawn-event"/u,
  );
  assert.match(source, /Promise\.all\(handoffs\.map/u);
});

test("prelaunch CJS oracle catches a missing suite import without touching disk", async () => {
  assert.deepEqual(inspectNativeCjsMissingIdentifiers(), []);
  const suitePath = fileURLToPath(new URL(
    "../qa/vscode-native/extension/suite.cjs",
    import.meta.url,
  ));
  const suite = await readFile(suitePath, "utf8");
  const mutated = suite.replace(
    "  AI_SETTING,\n  sha256Bytes,\n",
    "  AI_SETTING,\n",
  );
  assert.notEqual(mutated, suite, "Sensitivity mutation did not remove the import");
  const diagnostics = inspectNativeCjsMissingIdentifiers({
    sourceOverrides: { [suitePath]: mutated },
  });
  assert.ok(
    diagnostics.some((diagnostic) =>
      diagnostic.file === "suite.cjs"
      && [2304, 2552, 18004].includes(diagnostic.code)
      && diagnostic.message.includes("sha256Bytes")),
    `Missing sha256Bytes import was not detected: ${JSON.stringify(diagnostics)}`,
  );
});

test("prelaunch validates exact referenceable synthetic tool metadata", async () => {
  const manifest = JSON.parse(await readFile(new URL(
    "../qa/vscode-native/extension/package.json",
    import.meta.url,
  ), "utf8"));
  const proof = validateQaToolManifest(manifest);
  assert.equal(proof.result, "pass");
  assert.equal(
    proof.reviewedOfficialSource.commit,
    "c4453f8ea430795f941c1b2ff6c9321135a74a02",
  );
  assert.equal(proof.tools.length, 2);

  const missingFlag = structuredClone(manifest);
  delete missingFlag.contributes.languageModelTools[0].canBeReferencedInPrompt;
  assert.throws(
    () => validateQaToolManifest(missingFlag),
    /must set canBeReferencedInPrompt=true/u,
  );

  const missingReference = structuredClone(manifest);
  delete missingReference.contributes.languageModelTools[0].toolReferenceName;
  assert.throws(
    () => validateQaToolManifest(missingReference),
    /must provide toolReferenceName/u,
  );

  const duplicateReference = structuredClone(manifest);
  duplicateReference.contributes.languageModelTools[1].toolReferenceName =
    duplicateReference.contributes.languageModelTools[0].toolReferenceName;
  assert.throws(
    () => validateQaToolManifest(duplicateReference),
    /toolReferenceName must be unique/u,
  );
});

test("failed native assertion snapshots partial provider state without claiming pass", async () => {
  const suite = await readFile(new URL(
    "../qa/vscode-native/extension/suite.cjs",
    import.meta.url,
  ), "utf8");
  assert.match(
    suite,
    /finally \{\s+snapshotNativeState\(receipt, nativeState\);\s+await writeCapture/u,
  );
  const receipt: Record<string, any> = {
    schemaVersion: 1,
    result: "fail",
  };
  const nativeState = {
    providerRequests: [{ sequence: 1, tools: [] }],
    toolInvocations: {
      silmaril_native_qa_preblock_8d724ae7: 0,
      silmaril_native_qa_posttool_8d724ae7: 0,
    },
    providerCallCount: 1,
  };
  try {
    assert.equal(nativeState.toolInvocations.silmaril_native_qa_posttool_8d724ae7, 1);
  } catch (error) {
    receipt.error = {
      name: error instanceof Error ? error.name : "Error",
      message: error instanceof Error ? error.message : String(error),
    };
  } finally {
    snapshotNativeState(receipt, nativeState);
  }
  nativeState.providerRequests.push({ sequence: 2, tools: [] });

  assert.equal(receipt.result, "fail");
  assert.equal(receipt.error.name, "AssertionError");
  assert.deepEqual(receipt.providerRequests, [{ sequence: 1, tools: [] }]);
  assert.deepEqual(receipt.toolInvocations, {
    silmaril_native_qa_preblock_8d724ae7: 0,
    silmaril_native_qa_posttool_8d724ae7: 0,
  });
  assert.equal(receipt.providerCallCount, 1);
});

test("extension inventory is bounded and omits full private locations", () => {
  const privateLocation =
    "/private/profile-with-secret-name/extensions/github.copilot-chat-0.73.0";
  const inventory = buildSafeExtensionInventory([{
    id: "GitHub.copilot-chat",
    packageJSON: { version: "0.73.0", isBuiltin: true },
    extensionKind: 2,
    extensionUri: {
      scheme: "file",
      fsPath: privateLocation,
      path: privateLocation,
      query: "secret=must-not-appear",
    },
    isActive: false,
  }]);
  assert.deepEqual(inventory, [{
    id: "github.copilot-chat",
    version: "0.73.0",
    extensionKind: "workspace",
    isBuiltin: true,
    isActive: false,
    location: {
      scheme: "file",
      basename: "github.copilot-chat-0.73.0",
    },
    runningLocation: "not-exposed-by-public-vscode-extension-api",
  }]);
  assert.equal(JSON.stringify(inventory).includes("profile-with-secret-name"), false);
  assert.throws(
    () => buildSafeExtensionInventory(new Array(MAX_EXTENSIONS + 1)),
    /exceeds 10000 entries/u,
  );
});

test("launcher retains inventory and provider captures on native assertion failure", async () => {
  const launcher = await readFile(new URL(
    "../scripts/vscode-native-qualification.mjs",
    import.meta.url,
  ), "utf8");
  const finallyOffset = launcher.indexOf("} finally {");
  assert.ok(finallyOffset > 0);
  assert.ok(
    launcher.indexOf("if (await pathExists(capturePath)", finallyOffset)
      > finallyOffset,
  );
  assert.ok(
    launcher.indexOf("if (await pathExists(extensionInventoryPath)", finallyOffset)
      > finallyOffset,
  );
  assert.match(
    launcher,
    /SILMARIL_NATIVE_EXTENSION_INVENTORY_PATH: extensionInventoryPath/u,
  );
  assert.match(
    launcher,
    /waiting-for-normal-ui-disable-ai/u,
  );
  assert.match(
    launcher,
    /waiting-for-normal-ui-workspace-ai-enable/u,
  );
  assert.match(
    launcher,
    /resolvePortableQaPolicy\(env\)/u,
  );
});

test("portable QA defaults to preflight and rejects handoffs without the human gate", () => {
  assert.deepEqual(resolvePortableQaPolicy({}), {
    mode: "preflight",
    sessionRoute: "legacy-local",
    allowLaunch: false,
    allowNormalTrustHandoff: false,
    allowUiEnableHandoff: false,
    requireSharedModelHandoff: false,
    handoffs: {
      trust: undefined,
      disableAi: undefined,
      workspaceAi: undefined,
      sharedModel: undefined,
    },
  });
  assert.throws(
    () => resolvePortableQaPolicy({ NATIVE_TRUST_PENDING_PATH: "/tmp/trust" }),
    /Preflight-only mode must not provide/u,
  );
  assert.throws(
    () => resolvePortableQaPolicy({ SILMARIL_VSCODE_QA_ALLOW_HUMAN_UI: "true" }),
    /must be omitted or exactly 1/u,
  );
  assert.throws(
    () => resolvePortableQaPolicy({ SILMARIL_NATIVE_SESSION_ROUTE: "shared" }),
    /must be omitted or exactly shared-copilot/u,
  );
});

test("invalid route and handoff policy fail before fresh-root creation", async () => {
  const parent = await makeShortRealQaParent("svqa-policy-");
  try {
    const root = path.join(parent, "must-not-exist");
    const common = {
      VSCODE_APP: "/private/nonexistent/Visual Studio Code.app",
      VSCODE_NATIVE_PRIVATE_ROOT: root,
      NATIVE_QUALIFICATION_RECEIPT: path.join(root, "receipt.json"),
    };
    await assert.rejects(
      qualifyNativeVSCode({
        ...common,
        SILMARIL_NATIVE_SESSION_ROUTE: "invalid",
      }),
      /must be omitted or exactly shared-copilot/u,
    );
    await assert.rejects(
      qualifyNativeVSCode({
        ...common,
        SILMARIL_VSCODE_QA_ALLOW_HUMAN_UI: "1",
        SILMARIL_NATIVE_SESSION_ROUTE: "shared-copilot",
      }),
      /requires an absolute trust handoff/u,
    );
    await assert.rejects(
      lstat(root),
      (error: NodeJS.ErrnoException) => error.code === "ENOENT",
    );
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("portable human mode requires three distinct absolute handoffs", () => {
  const env = {
    SILMARIL_VSCODE_QA_ALLOW_HUMAN_UI: "1",
    NATIVE_TRUST_PENDING_PATH: "/private/qa/handoffs/trust.json",
    NATIVE_AGENT_ENABLE_PENDING_PATH: "/private/qa/handoffs/disable.json",
    NATIVE_WORKSPACE_AI_ENABLE_PENDING_PATH:
      "/private/qa/handoffs/workspace.json",
  };
  const policy = resolvePortableQaPolicy(env);
  assert.equal(policy.mode, "human-ui");
  assert.equal(policy.allowLaunch, true);
  assert.equal(policy.allowNormalTrustHandoff, true);
  assert.equal(policy.allowUiEnableHandoff, true);
  assert.equal(policy.sessionRoute, "legacy-local");
  assert.equal(policy.requireSharedModelHandoff, false);
  assert.throws(
    () => resolvePortableQaPolicy({
      ...env,
      NATIVE_WORKSPACE_AI_ENABLE_PENDING_PATH:
        env.NATIVE_AGENT_ENABLE_PENDING_PATH,
    }),
    /must be distinct/u,
  );
  assert.throws(
    () => resolvePortableQaPolicy({
      ...env,
      NATIVE_TRUST_PENDING_PATH: "relative.json",
    }),
    /requires an absolute trust/u,
  );
});

test("shared route requires a fourth contained UI handoff before launch", () => {
  const root = "/private/qa";
  const base = {
    SILMARIL_VSCODE_QA_ALLOW_HUMAN_UI: "1",
    SILMARIL_NATIVE_SESSION_ROUTE: "shared-copilot",
    NATIVE_TRUST_PENDING_PATH: `${root}/trust.json`,
    NATIVE_AGENT_ENABLE_PENDING_PATH: `${root}/disable.json`,
    NATIVE_WORKSPACE_AI_ENABLE_PENDING_PATH: `${root}/workspace.json`,
  };
  assert.throws(
    () => resolvePortableQaPolicy(base),
    /requires an absolute sharedModel handoff/u,
  );
  const policy = resolvePortableQaPolicy({
    ...base,
    NATIVE_SHARED_MODEL_PENDING_PATH: `${root}/shared-model.json`,
  });
  assert.equal(policy.sessionRoute, "shared-copilot");
  assert.equal(policy.requireSharedModelHandoff, true);
  assert.equal(
    policy.handoffs.sharedModel,
    `${root}/shared-model.json`,
  );
  assert.throws(
    () => resolvePortableQaPolicy({
      ...base,
      NATIVE_SHARED_MODEL_PENDING_PATH: base.NATIVE_TRUST_PENDING_PATH,
    }),
    /must be distinct/u,
  );
});

test("shared route uses only exact observed wrapped metadata and attestation is not proof", async () => {
  const constants = {
    VENDOR: "silmaril-native-qa-dummy-8d724ae7",
    MODEL_ID: "silmaril-native-qa-local-deterministic-8d724ae7",
  };
  const wrappedId = `${constants.VENDOR}/${constants.MODEL_ID}`;
  assert.deepEqual(
    modelSelectorForRoute(constants, "legacy-local"),
    {
      vendor: constants.VENDOR,
      id: constants.MODEL_ID,
    },
    "Default driver must retain the unwrapped Local selector",
  );
  assert.deepEqual(
    modelSelectorForRoute(constants, "shared-copilot"),
    {
      vendor: "agent-host-copilotcli",
      id: wrappedId,
    },
  );
  const publicModel = {
    name: "Silmaril Native QA Local Deterministic Dummy",
    vendor: "agent-host-copilotcli",
    id: wrappedId,
    family: wrappedId,
    version: "1.0",
    maxInputTokens: 32_768,
  };
  const modelReceipt = validateWrappedModels([publicModel], constants);
  assert.equal(modelReceipt.vendor, "agent-host-copilotcli");
  assert.equal(modelReceipt.id, wrappedId);
  assert.equal(
    Object.hasOwn(modelReceipt, "targetChatSessionType"),
    false,
    "Stable public metadata must not invent internal bridge fields",
  );
  assert.deepEqual(
    modelSelectorFromPublicModel(modelReceipt),
    {
      vendor: publicModel.vendor,
      id: publicModel.id,
    },
    "Turn selector must come from validated observed public metadata",
  );
  assert.throws(
    () => validateWrappedModels([], constants),
    /exactly one host-published wrapped/u,
  );
  assert.throws(
    () => validateWrappedModels([{
      ...publicModel,
      vendor: constants.VENDOR,
      id: constants.MODEL_ID,
    }], constants),
  );

  const attestation = {
    schemaVersion: 1,
    state: "normal-visible-shared-model-selected",
    kind: "human-ui-selection-action-only",
    normalUiActions: {
      sessionHarness: {
        surface: "Chat session/harness picker",
        syntheticCommandUsed: false,
        observedTargetSessionType: "agent-host-copilotcli",
        observationSource: "normal-visible-ui",
      },
      model: {
        surface: "Chat model picker",
        syntheticCommandUsed: false,
      },
    },
    selectedPublicModel: {
      vendor: publicModel.vendor,
      id: publicModel.id,
    },
    executionProof: false,
  };
  assert.equal(
    validateSelectionActionAttestation(attestation, publicModel)
      .executionProof,
    false,
  );
  assert.throws(
    () => validateSelectionActionAttestation({
      ...attestation,
      executionProof: true,
    }, publicModel),
    /must never claim execution proof/u,
  );
  assert.throws(
    () => validateSelectionActionAttestation({
      ...attestation,
      normalUiActions: {
        ...attestation.normalUiActions,
        sessionHarness: {
          ...attestation.normalUiActions.sessionHarness,
          observedTargetSessionType: "local",
        },
      },
    }, publicModel),
  );
  assert.throws(
    () => validateSelectionActionAttestation({
      ...attestation,
      normalUiActions: {
        ...attestation.normalUiActions,
        sessionHarness: {
          ...attestation.normalUiActions.sessionHarness,
          observationSource: "synthetic-api",
        },
      },
    }, publicModel),
    /must be observed in normal visible UI or the fresh-profile host log/u,
  );
  const suite = await readFile(new URL(
    "../qa/vscode-native/extension/suite.cjs",
    import.meta.url,
  ), "utf8");
  const handoff = suite.indexOf("await prepareSharedModelHandoff");
  const observedSelector = suite.indexOf(
    "modelSelector = modelSelectorFromPublicModel(publicModel)",
    handoff,
  );
  const firstTurn = suite.indexOf(
    "await runTurn(modelSelector, input.query, input.tools)",
    observedSelector,
  );
  assert.ok(
    handoff > 0 && handoff < observedSelector && observedSelector < firstTurn,
    "Shared turn selector must be assigned from observed metadata after handoff",
  );
});

test("activeAgent is written only to the fresh shared-route profile", () => {
  const common = {
    candidate: "/private/fresh/candidate",
    proxyUrl: "http://127.0.0.1:12345",
  };
  const legacy = buildNativeProfileSettings({
    ...common,
    sessionRoute: "legacy-local",
  });
  assert.equal(
    Object.hasOwn(
      legacy,
      "chat.agentHost.experimental.titleGeneration",
    ),
    false,
  );
  const shared = buildNativeProfileSettings({
    ...common,
    sessionRoute: "shared-copilot",
  });
  assert.equal(
    shared["chat.agentHost.experimental.titleGeneration"],
    "activeAgent",
  );
});

async function makeShortRealQaParent(prefix: string) {
  const temporaryRoot = process.platform === "darwin"
    ? "/private/tmp"
    : await realpath(os.tmpdir());
  return await realpath(await mkdtemp(path.join(temporaryRoot, prefix)));
}

test("fresh layout is exclusive, contained, private, and supports spaces and Unicode", async () => {
  const parent = await makeShortRealQaParent("svqa-fresh-");
  try {
    const root = path.join(parent, "fresh QA β");
    const receiptPath = path.join(root, "evidence", "receipt.json");
    const policy = resolvePortableQaPolicy({});
    const layout = await createFreshQaLayout({
      privateRoot: root,
      receiptPath,
      policy,
    });
    assert.equal(layout.root, root);
    assert.equal((await lstat(root)).mode & 0o777, 0o700);
    await writeFile(path.join(root, "sentinel"), "preserve");
    await assert.rejects(
      createFreshQaLayout({ privateRoot: root, receiptPath, policy }),
      /already exists/u,
    );
    assert.equal(await readFile(path.join(root, "sentinel"), "utf8"), "preserve");
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

for (const overflowCase of [
  {
    name: "ASCII",
    rootName: "a".repeat(110),
  },
  {
    name: "multibyte Unicode",
    rootName: "界".repeat(40),
  },
] as const) {
  test(`fresh layout rejects ${overflowCase.name} IPC path overflow before mkdir`, async () => {
    const parent = await makeShortRealQaParent("svqa-ipc-");
    try {
      const root = path.join(parent, overflowCase.rootName);
      await assert.rejects(
        createFreshQaLayout({
          privateRoot: root,
          receiptPath: path.join(root, "evidence", "receipt.json"),
          policy: resolvePortableQaPolicy({}),
        }),
        /IPC path is \d+ UTF-8 bytes; maximum is 103/u,
      );
      await assert.rejects(
        lstat(root),
        (error: NodeJS.ErrnoException) => error.code === "ENOENT",
      );
    } finally {
      await rm(parent, { recursive: true, force: true });
    }
  });
}

test("fresh layout rejects escaped outputs and symlinked parents", async () => {
  const temporary = await makeShortRealQaParent("svqa-bounds-");
  try {
    const policy = resolvePortableQaPolicy({});
    const root = path.join(temporary, "fresh");
    await assert.rejects(
      createFreshQaLayout({
        privateRoot: root,
        receiptPath: path.join(temporary, "outside.json"),
        policy,
      }),
      /receipt must be strictly inside/u,
    );
    const actualParent = path.join(temporary, "actual");
    const aliasParent = path.join(temporary, "alias");
    await mkdir(actualParent);
    await symlink(actualParent, aliasParent);
    const aliasRoot = path.join(aliasParent, "fresh");
    await assert.rejects(
      createFreshQaLayout({
        privateRoot: aliasRoot,
        receiptPath: path.join(aliasRoot, "receipt.json"),
        policy,
      }),
      /parent must not be a symlink/u,
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("fresh layout contains all human handoffs", async () => {
  const parent = await makeShortRealQaParent("svqa-handoff-");
  try {
    const root = path.join(parent, "fresh");
    const base = {
      SILMARIL_VSCODE_QA_ALLOW_HUMAN_UI: "1",
      SILMARIL_NATIVE_SESSION_ROUTE: "shared-copilot",
      NATIVE_TRUST_PENDING_PATH: path.join(root, "handoffs", "trust.json"),
      NATIVE_AGENT_ENABLE_PENDING_PATH:
        path.join(root, "handoffs", "disable.json"),
      NATIVE_WORKSPACE_AI_ENABLE_PENDING_PATH:
        path.join(root, "handoffs", "workspace.json"),
      NATIVE_SHARED_MODEL_PENDING_PATH:
        path.join(root, "handoffs", "shared-model.json"),
    };
    const policy = resolvePortableQaPolicy(base);
    await createFreshQaLayout({
      privateRoot: root,
      receiptPath: path.join(root, "receipt.json"),
      policy,
    });
    const escapedRoot = path.join(parent, "escaped");
    await assert.rejects(
      createFreshQaLayout({
        privateRoot: escapedRoot,
        receiptPath: path.join(escapedRoot, "receipt.json"),
        policy,
      }),
      /handoff must be strictly inside/u,
    );
    const collisionRoot = path.join(parent, "collision");
    const collisionReceipt = path.join(collisionRoot, "receipt.json");
    const collisionPolicy = resolvePortableQaPolicy({
      SILMARIL_VSCODE_QA_ALLOW_HUMAN_UI: "1",
      SILMARIL_NATIVE_SESSION_ROUTE: "shared-copilot",
      NATIVE_TRUST_PENDING_PATH: collisionReceipt,
      NATIVE_AGENT_ENABLE_PENDING_PATH:
        path.join(collisionRoot, "disable.json"),
      NATIVE_WORKSPACE_AI_ENABLE_PENDING_PATH:
        path.join(collisionRoot, "workspace.json"),
      NATIVE_SHARED_MODEL_PENDING_PATH:
        path.join(collisionRoot, "shared-model.json"),
    });
    await assert.rejects(
      createFreshQaLayout({
        privateRoot: collisionRoot,
        receiptPath: collisionReceipt,
        policy: collisionPolicy,
      }),
      /receipt and handoff paths must be distinct/u,
    );
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("child environment is allowlisted and omits caller credentials", () => {
  const child = buildMinimalChildEnvironment({
    PATH: "/usr/bin",
    LANG: "en_US.UTF-8",
    HOME: "/real/home",
    AWS_SECRET_ACCESS_KEY: "secret",
    GITHUB_TOKEN: "secret",
    GH_TOKEN: "secret",
    NPM_TOKEN: "secret",
    VENDOR_API_KEY: "secret",
  }, {
    HOME: "/private/fresh/home",
    TMPDIR: "/private/fresh/tmp",
    IS_SCENARIO_AUTOMATION: "1",
  });
  assert.deepEqual(child, {
    PATH: "/usr/bin",
    LANG: "en_US.UTF-8",
    HOME: "/private/fresh/home",
    TMPDIR: "/private/fresh/tmp",
    IS_SCENARIO_AUTOMATION: "1",
  });
});

const observerBeforeProfile = Buffer.from(JSON.stringify({
  "http.proxy": "http://127.0.0.1:2001",
}));
const observerAfterProfile = Buffer.from(JSON.stringify({
  "http.proxy": "http://127.0.0.1:2001",
  "chat.disableAIFeatures": true,
}));
const observerBeforeWorkspace = Buffer.from(JSON.stringify({
  folders: [{ path: "workspace" }],
  settings: { "window.title": "Synthetic QA" },
}));
const observerAfterWorkspace = Buffer.from(JSON.stringify({
  folders: [{ path: "workspace" }],
  settings: {
    "window.title": "Synthetic QA",
    "chat.disableAIFeatures": false,
  },
}));
const observerPaths = {
  profileResolvedPath: "/private/user-data/User",
  profileSettingsPath: "/private/user-data/User/settings.json",
  userDataPath: "/private/user-data",
  workspaceFilePath: "/private/workspace/native.code-workspace",
};
const initialAiConfiguration = {
  source: "test",
  key: "chat.disableAIFeatures",
  effectiveValue: false,
  defaultValue: false,
  globalValue: null,
  workspaceValue: null,
  workspaceFolderValue: null,
};
const disabledAiConfiguration = {
  ...initialAiConfiguration,
  effectiveValue: true,
  globalValue: true,
};
const workspaceEnabledAiConfiguration = {
  ...initialAiConfiguration,
  effectiveValue: false,
  globalValue: true,
  workspaceValue: false,
};
const testSignedExtensionIdentity = {
  id: "github.copilot-chat",
  version: "0.73.0",
  isBuiltin: true,
  canonicalPath: "/signed/VSCode.app/extensions/copilot",
  manifestSha256: "manifest-sha256",
  sourceSha256: "source-sha256",
};

function testSignedExtensionProof(
  overrides: Partial<typeof testSignedExtensionIdentity> = {},
) {
  return {
    identity: {
      ...testSignedExtensionIdentity,
      ...overrides,
    },
  };
}

function waitForMilliseconds(milliseconds: number) {
  return new Promise<void>((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

function phaseOneObserverOptions(
  readObservation: () => Promise<Record<string, unknown>>,
  subscribeConfiguration?: (
    listener: () => void,
  ) => { dispose(): void },
) {
  return {
    phase: "disable-profile",
    paths: observerPaths,
    beforeProfileSettingsBytes: observerBeforeProfile,
    beforeWorkspaceBytes: observerBeforeWorkspace,
    readObservation,
    stages: [
      {
        label: "matching-public-profile-configuration",
        timeoutMs: 40,
        timeOrigin: "test-primary",
        isSatisfied: (proof: Record<string, any>) =>
          proof.configurationMatches,
      },
      {
        label: "exact-private-profile-file-delta",
        timeoutMs: 20,
        timeOrigin: "test-convergence",
        isSatisfied: (proof: Record<string, any>) =>
          proof.exactFileDeltaMatches,
      },
    ],
    pollIntervalMs: 2,
    timeOrigin: "test-observer-start",
    subscribeConfiguration,
  };
}

function phaseTwoObserverOptions(
  readObservation: () => Promise<Record<string, unknown>>,
) {
  return {
    phase: "enable-workspace",
    paths: observerPaths,
    beforeProfileSettingsBytes: observerBeforeProfile,
    beforeWorkspaceBytes: observerBeforeWorkspace,
    readObservation,
    stages: [
      {
        label: "signed-built-in-extension-registration",
        timeoutMs: 40,
        timeOrigin: "test-extension",
        isSatisfied: (proof: Record<string, any>) =>
          proof.extensionIdentityMatches,
      },
      {
        label: "matching-public-workspace-configuration",
        timeoutMs: 20,
        timeOrigin: "test-configuration",
        isSatisfied: (proof: Record<string, any>) =>
          proof.configurationMatches,
      },
      {
        label: "exact-workspace-file-delta",
        timeoutMs: 20,
        timeOrigin: "test-files",
        isSatisfied: (proof: Record<string, any>) =>
          proof.exactFileDeltaMatches,
      },
    ],
    pollIntervalMs: 2,
    timeOrigin: "test-phase-two-start",
  };
}

function boundedObserverOptions(
  readObservation: () => Promise<Record<string, unknown>>,
  timeoutMs: number,
  subscribeConfiguration?: (
    listener: () => void,
  ) => { dispose(): void },
) {
  return {
    phase: "disable-profile",
    paths: observerPaths,
    beforeProfileSettingsBytes: observerBeforeProfile,
    beforeWorkspaceBytes: observerBeforeWorkspace,
    readObservation,
    stages: [
      {
        label: "bounded-test-proof",
        timeoutMs,
        timeOrigin: "bounded-test-start",
        isSatisfied: (proof: Record<string, any>) => proof.success,
      },
    ],
    pollIntervalMs: 20,
    timeOrigin: "bounded-test-start",
    subscribeConfiguration,
  };
}

test("normal UI observer succeeds by polling when the event is missed", async () => {
  let reads = 0;
  const result = await observeNormalUiPhase(phaseOneObserverOptions(async () => {
    reads += 1;
    return {
      configuration:
        reads >= 2 ? disabledAiConfiguration : initialAiConfiguration,
      observedProfileSettingsBytes:
        reads >= 2 ? observerAfterProfile : observerBeforeProfile,
      observedWorkspaceBytes: observerBeforeWorkspace,
      extensionIdentityState: "not-required",
    };
  }));
  assert.equal(result.proof.success, true);
  assert.equal(
    result.diagnostic.observer.completionSource,
    "periodic-read-without-observed-event",
  );
  assert.equal(
    result.diagnostic.supportedInterpretation,
    "ordinary-event-not-observed-periodic-read-completed",
  );
  assert.equal(result.diagnostic.observer.eventCounts.configuration, 0);
});

test("normal UI observer rejects event-only public configuration", async () => {
  let listener: (() => void) | undefined;
  let configuration: Record<string, unknown> = initialAiConfiguration;
  const pending = observeNormalUiPhase(phaseOneObserverOptions(
    async () => ({
      configuration,
      observedProfileSettingsBytes: observerBeforeProfile,
      observedWorkspaceBytes: observerBeforeWorkspace,
      extensionIdentityState: "not-required",
    }),
    (candidate) => {
      listener = candidate;
      return { dispose() {} };
    },
  ));
  setTimeout(() => {
    configuration = disabledAiConfiguration;
    listener?.();
  }, 2);
  await assert.rejects(pending, (error: any) => {
    assert.equal(
      error.normalUiPhaseDiagnostic.evidenceClassification,
      "public-configuration-matched-exact-file-delta-missing",
    );
    assert.equal(
      error.normalUiPhaseDiagnostic.supportedInterpretation,
      "wrong-profile-or-profile-source-mismatch-possible-not-proven",
    );
    assert.equal(
      error.normalUiPhaseDiagnostic.observer.eventCounts.configuration,
      1,
    );
    return true;
  });
});

test("normal UI observer rejects file-only and conflicting public scope", async () => {
  for (const configuration of [
    initialAiConfiguration,
    {
      ...disabledAiConfiguration,
      globalValue: null,
      workspaceValue: true,
    },
  ]) {
    await assert.rejects(
      observeNormalUiPhase(phaseOneObserverOptions(async () => ({
        configuration,
        observedProfileSettingsBytes: observerAfterProfile,
        observedWorkspaceBytes: observerBeforeWorkspace,
        extensionIdentityState: "not-required",
      }))),
      (error: any) => {
        assert.equal(
          error.normalUiPhaseDiagnostic.evidenceClassification,
          "exact-file-delta-observed-public-scope-conflict",
        );
        return true;
      },
    );
  }
});

test("normal UI observer rejects a matching observation that completes after its deadline", async () => {
  let lateFulfilled = false;
  let settlement = "pending";
  const startedAt = Date.now();
  const pending = observeNormalUiPhase(boundedObserverOptions(
    async () => {
      await waitForMilliseconds(140);
      lateFulfilled = true;
      return {
        configuration: disabledAiConfiguration,
        observedProfileSettingsBytes: observerAfterProfile,
        observedWorkspaceBytes: observerBeforeWorkspace,
        extensionIdentityState: "not-required",
      };
    },
    80,
  ));
  await assert.rejects(pending, (error: any) => {
    settlement = "rejected";
    assert.equal(
      error.normalUiPhaseDiagnostic.failure.code,
      "NORMAL_UI_OBSERVATION_READ_TIMEOUT",
    );
    return true;
  });
  const elapsedMs = Date.now() - startedAt;
  assert.ok(elapsedMs >= 60 && elapsedMs < 300);
  await waitForMilliseconds(100);
  assert.equal(lateFulfilled, true);
  assert.equal(settlement, "rejected");
});

test("normal UI observer bounds a never-settling read and disposes subscriptions", async () => {
  let disposed = false;
  const startedAt = Date.now();
  await assert.rejects(
    observeNormalUiPhase(boundedObserverOptions(
      async () => await new Promise(() => {}),
      80,
      () => ({
        dispose() {
          disposed = true;
        },
      }),
    )),
    (error: any) => {
      assert.equal(
        error.normalUiPhaseDiagnostic.failure.category,
        "observation-read-timeout",
      );
      return true;
    },
  );
  const elapsedMs = Date.now() - startedAt;
  assert.ok(elapsedMs >= 60 && elapsedMs < 300);
  assert.equal(disposed, true);
});

test("normal UI observer accepts a timely matching bounded read", async () => {
  const result = await observeNormalUiPhase(boundedObserverOptions(
    async () => {
      await waitForMilliseconds(20);
      return {
        configuration: disabledAiConfiguration,
        observedProfileSettingsBytes: observerAfterProfile,
        observedWorkspaceBytes: observerBeforeWorkspace,
        extensionIdentityState: "not-required",
      };
    },
    150,
  ));
  assert.equal(result.proof.success, true);
});

test("normal UI observer sanitizes read failures and records only available evidence", async () => {
  let disposed = false;
  await assert.rejects(
    observeNormalUiPhase(boundedObserverOptions(
      async () => {
        throw new Error("RAW_PRIVATE_READ_ERROR_MUST_NOT_LEAK");
      },
      150,
      () => ({
        dispose() {
          disposed = true;
        },
      }),
    )),
    (error: any) => {
      assert.equal(
        error.normalUiPhaseDiagnostic.failure.code,
        "NORMAL_UI_OBSERVATION_READ_FAILED",
      );
      assert.equal(
        error.normalUiPhaseDiagnostic.failure.category,
        "observation-read-failure",
      );
      assert.equal(
        Object.hasOwn(
          error.normalUiPhaseDiagnostic.files.profileSettings,
          "observedSha256",
        ),
        false,
      );
      assert.doesNotMatch(
        JSON.stringify(error.normalUiPhaseDiagnostic),
        /RAW_PRIVATE_READ_ERROR_MUST_NOT_LEAK/u,
      );
      assert.doesNotMatch(
        error.message,
        /RAW_PRIVATE_READ_ERROR_MUST_NOT_LEAK/u,
      );
      return true;
    },
  );
  assert.equal(disposed, true);
});

test("normal UI observer sanitizes invalid observed JSON while retaining hashes", async () => {
  const invalidProfileBytes = Buffer.from(
    '{"RAW_PRIVATE_FILE_CONTENT_MUST_NOT_LEAK":',
  );
  await assert.rejects(
    observeNormalUiPhase(boundedObserverOptions(
      async () => ({
        configuration: disabledAiConfiguration,
        observedProfileSettingsBytes: invalidProfileBytes,
        observedWorkspaceBytes: observerBeforeWorkspace,
        extensionIdentityState: "not-required",
      }),
      150,
    )),
    (error: any) => {
      const diagnostic = error.normalUiPhaseDiagnostic;
      assert.equal(
        diagnostic.failure.code,
        "NORMAL_UI_OBSERVATION_CLASSIFICATION_FAILED",
      );
      assert.equal(
        diagnostic.failure.category,
        "observation-classification-failure",
      );
      assert.equal(
        typeof diagnostic.files.profileSettings.observedSha256,
        "string",
      );
      assert.equal(
        Object.hasOwn(diagnostic.files.profileSettings, "delta"),
        false,
      );
      assert.equal(diagnostic.configuration.globalValue, true);
      assert.doesNotMatch(
        JSON.stringify(diagnostic),
        /RAW_PRIVATE_FILE_CONTENT_MUST_NOT_LEAK/u,
      );
      return true;
    },
  );
});

test("normal UI phase classification distinguishes unchanged and wrong-profile evidence", () => {
  const unchanged = classifyNormalUiPhase({
    phase: "disable-profile",
    beforeProfileSettingsBytes: observerBeforeProfile,
    beforeWorkspaceBytes: observerBeforeWorkspace,
    observedProfileSettingsBytes: observerBeforeProfile,
    observedWorkspaceBytes: observerBeforeWorkspace,
    configuration: initialAiConfiguration,
  });
  assert.equal(unchanged.success, false);
  assert.equal(
    unchanged.evidenceClassification,
    "no-approved-action-observed",
  );

  const wrongProfile = classifyNormalUiPhase({
    phase: "disable-profile",
    beforeProfileSettingsBytes: observerBeforeProfile,
    beforeWorkspaceBytes: observerBeforeWorkspace,
    observedProfileSettingsBytes: observerBeforeProfile,
    observedWorkspaceBytes: observerBeforeWorkspace,
    configuration: disabledAiConfiguration,
  });
  assert.equal(wrongProfile.success, false);
  assert.equal(
    wrongProfile.evidenceClassification,
    "public-configuration-matched-exact-file-delta-missing",
  );
});

test("phase two passes without events only with live signed identity, exact scope, and both deltas", async () => {
  const extension = { id: "github.copilot-chat" };
  let currentExtension: object | undefined = extension;
  let verificationCount = 0;
  const identity = createLiveExtensionIdentityTracker({
    getCurrentExtension: () => currentExtension,
    verifyExtension: async (candidate: object) => {
      assert.equal(candidate, extension);
      verificationCount += 1;
      return testSignedExtensionProof();
    },
  });
  const result = await observeNormalUiPhase(phaseTwoObserverOptions(
    async () => {
      const currentIdentity = await identity.observe();
      return {
        configuration: workspaceEnabledAiConfiguration,
        observedProfileSettingsBytes: observerAfterProfile,
        observedWorkspaceBytes: observerAfterWorkspace,
        extensionIdentityState: currentIdentity.state,
      };
    },
  ));
  assert.equal(result.proof.success, true);
  assert.equal(
    result.diagnostic.observer.completionSource,
    "periodic-read-without-observed-event",
  );
  assert.equal(verificationCount, 1, "Stable polls must reuse signed proof");
  const finalIdentity = await identity.verifyCurrentAccepted();
  assert.equal(finalIdentity.extension, extension);
  assert.equal(finalIdentity.proofSource, "fresh-final-verification");
  assert.equal(verificationCount, 3);
  currentExtension = undefined;
});

test("phase two rejects a missing or conflicting extension identity", async () => {
  for (const scenario of ["missing", "conflict"]) {
    const extension = scenario === "missing"
      ? undefined
      : { id: "github.copilot-chat-conflict" };
    const identity = createLiveExtensionIdentityTracker({
      getCurrentExtension: () => extension,
      verifyExtension: async () => {
        throw new Error("not the signed extension");
      },
    });
    await assert.rejects(
      observeNormalUiPhase(phaseTwoObserverOptions(async () => {
        const currentIdentity = await identity.observe();
        return {
          configuration: workspaceEnabledAiConfiguration,
          observedProfileSettingsBytes: observerAfterProfile,
          observedWorkspaceBytes: observerAfterWorkspace,
          extensionIdentityState: currentIdentity.state,
        };
      })),
      (error: any) => {
        assert.equal(
          error.normalUiPhaseDiagnostic.evidenceClassification,
          scenario === "missing"
            ? "signed-extension-not-registered"
            : "signed-extension-identity-conflict",
        );
        return true;
      },
    );
  }
});

test("phase two rejects wrong public scope and partial exact deltas", async () => {
  for (const scenario of ["wrong-scope", "partial-deltas"]) {
    const extension = { id: "github.copilot-chat" };
    const identity = createLiveExtensionIdentityTracker({
      getCurrentExtension: () => extension,
      verifyExtension: async () => testSignedExtensionProof(),
    });
    await assert.rejects(
      observeNormalUiPhase(phaseTwoObserverOptions(async () => {
        const currentIdentity = await identity.observe();
        return {
          configuration: scenario === "wrong-scope"
            ? {
                ...workspaceEnabledAiConfiguration,
                globalValue: null,
              }
            : workspaceEnabledAiConfiguration,
          observedProfileSettingsBytes: observerAfterProfile,
          observedWorkspaceBytes: scenario === "partial-deltas"
            ? observerBeforeWorkspace
            : observerAfterWorkspace,
          extensionIdentityState: currentIdentity.state,
        };
      })),
      (error: any) => {
        assert.equal(
          error.normalUiPhaseDiagnostic.evidenceClassification,
          scenario === "wrong-scope"
            ? "exact-file-delta-observed-public-scope-conflict"
            : "public-configuration-matched-exact-file-delta-missing",
        );
        return true;
      },
    );
  }
});

test("phase two cannot pass after the accepted extension is removed before convergence", async () => {
  const extension = { id: "github.copilot-chat" };
  let currentExtension: object | undefined = extension;
  let reads = 0;
  const identity = createLiveExtensionIdentityTracker({
    getCurrentExtension: () => currentExtension,
    verifyExtension: async () => testSignedExtensionProof(),
  });
  await assert.rejects(
    observeNormalUiPhase(phaseTwoObserverOptions(async () => {
      reads += 1;
      if (reads >= 2) currentExtension = undefined;
      const currentIdentity = await identity.observe();
      return {
        configuration: workspaceEnabledAiConfiguration,
        observedProfileSettingsBytes: observerAfterProfile,
        observedWorkspaceBytes: observerAfterWorkspace,
        extensionIdentityState: currentIdentity.state,
      };
    })),
    /without complete approved proof/u,
  );
});

test("live extension tracker accepts equivalent fresh wrappers by immutable identity", async () => {
  let wrapperSequence = 0;
  let verificationCount = 0;
  const identity = createLiveExtensionIdentityTracker({
    getCurrentExtension: () => ({
      id: "github.copilot-chat",
      wrapperSequence: ++wrapperSequence,
    }),
    verifyExtension: async () => {
      verificationCount += 1;
      return testSignedExtensionProof();
    },
  });
  assert.equal((await identity.observe()).proofSource, "fresh-verification");
  assert.equal((await identity.observe()).proofSource, "fresh-verification");
  assert.equal(verificationCount, 2);
  const finalIdentity = await identity.verifyCurrentAccepted();
  assert.equal(finalIdentity.proofSource, "fresh-final-verification");
  assert.equal(verificationCount, 4);
});

test("live extension tracker rejects immutable identity replacement during final verification", async () => {
  let getterCalls = 0;
  const identity = createLiveExtensionIdentityTracker({
    getCurrentExtension: () => ({
      id: "github.copilot-chat",
      identityGeneration: ++getterCalls >= 3 ? 2 : 1,
    }),
    verifyExtension: async (extension: any) =>
      testSignedExtensionProof(
        extension.identityGeneration === 2
          ? { sourceSha256: "replacement-source-sha256" }
          : {},
      ),
  });
  assert.equal((await identity.observe()).state, "verified");
  await assert.rejects(
    identity.verifyCurrentAccepted(),
    /immutable identity changed during final phase-two verification/u,
  );
});

test("live extension tracker rejects removal before final verification", async () => {
  const extension = { id: "github.copilot-chat" };
  let currentExtension: object | undefined = extension;
  const identity = createLiveExtensionIdentityTracker({
    getCurrentExtension: () => currentExtension,
    verifyExtension: async () => testSignedExtensionProof(),
  });
  assert.equal((await identity.observe()).state, "verified");
  currentExtension = undefined;
  await assert.rejects(
    identity.verifyCurrentAccepted(),
    /absent at final phase-two verification/u,
  );
});

test("native PASS clamp rejects unchanged or partial UI transitions", () => {
  const unchanged = classifyFreshProfileUiFiles({
    activeSettingsBytes: observerBeforeProfile,
    activeConfigBytes: Buffer.from("{}"),
    originalWorkspaceBytes: observerBeforeWorkspace,
    observedSettingsBytes: observerBeforeProfile,
    observedConfigBytes: Buffer.from("{}"),
    observedWorkspaceBytes: observerBeforeWorkspace,
  });
  assert.equal(unchanged.expected, true);
  assert.equal(unchanged.expectedUiTransitionObserved, false);
  assert.equal(classificationAllowsNativePass(unchanged), false);

  const partial = classifyFreshProfileUiFiles({
    activeSettingsBytes: observerBeforeProfile,
    activeConfigBytes: Buffer.from("{}"),
    originalWorkspaceBytes: observerBeforeWorkspace,
    observedSettingsBytes: observerAfterProfile,
    observedConfigBytes: Buffer.from("{}"),
    observedWorkspaceBytes: observerBeforeWorkspace,
  });
  assert.equal(partial.expected, true);
  assert.equal(partial.expectedUiTransitionObserved, false);
  assert.equal(classificationAllowsNativePass(partial), false);
});

test("handoff paths resolve to the exact private profile sources", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svqa-handoff-"));
  try {
    const userData = path.join(temporary, "user-data");
    const profile = path.join(userData, "User");
    const workspace = path.join(temporary, "workspace");
    const profileSettingsPath = path.join(profile, "settings.json");
    const workspaceFile = path.join(workspace, "native.code-workspace");
    await Promise.all([
      mkdir(profile, { recursive: true }),
      mkdir(workspace, { recursive: true }),
    ]);
    await Promise.all([
      writeFile(profileSettingsPath, "{}"),
      writeFile(workspaceFile, "{}"),
    ]);
    assert.deepEqual(
      await resolveNativeHandoffPaths({
        ownedProfileRoot: temporary,
        userData,
        profileSettingsPath,
        workspaceFile,
      }),
      {
        profileResolvedPath: await realpath(profile),
        profileSettingsPath: await realpath(profileSettingsPath),
        userDataPath: await realpath(userData),
        workspaceFilePath: await realpath(workspaceFile),
      },
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("two-phase UI deltas are exact and preserve every unrelated field", () => {
  const activeSettings = Buffer.from(JSON.stringify({
    "http.proxy": "http://127.0.0.1:2001",
    "chat.allowAnonymousAccess": true,
    "chat.agentHost.experimental.titleGeneration": "activeAgent",
  }));
  const activeConfig = Buffer.from(JSON.stringify({
    apiUrl: "http://127.0.0.1:2002/classify",
    mode: "block",
  }));
  const originalWorkspace = Buffer.from(JSON.stringify({
    folders: [{ path: "workspace" }],
    settings: { "window.title": "Synthetic QA" },
  }));
  const proof = classifyFreshProfileUiFiles({
    activeSettingsBytes: activeSettings,
    activeConfigBytes: activeConfig,
    originalWorkspaceBytes: originalWorkspace,
    observedSettingsBytes: Buffer.from(JSON.stringify({
      "http.proxy": "http://127.0.0.1:2001",
      "chat.allowAnonymousAccess": true,
      "chat.agentHost.experimental.titleGeneration": "activeAgent",
      "chat.disableAIFeatures": true,
    })),
    observedConfigBytes: activeConfig,
    observedWorkspaceBytes: Buffer.from(JSON.stringify({
      folders: [{ path: "workspace" }],
      settings: {
        "window.title": "Synthetic QA",
        "chat.disableAIFeatures": false,
      },
    })),
  });
  assert.equal(proof.expected, true);
  assert.equal(proof.expectedUiTransitionObserved, true);
  assert.equal(proof.phaseOrderValid, true);
  assert.equal(proof.settings.state, "expected-ui-delta");
  assert.equal(proof.workspace.state, "expected-ui-delta");
  assert.equal(proof.config.state, "unchanged");
});

test("unexpected UI changes are archived before byte-exact restoration", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svqa-ui-policy-"));
  try {
    const settingsPath = path.join(temporary, "settings.json");
    const configPath = path.join(temporary, "config.json");
    const workspacePath = path.join(temporary, "native.code-workspace");
    const archiveDirectory = path.join(temporary, "archive");
    const originalSettings = Buffer.from('{"http.proxy":"old"}\n');
    const originalConfig = Buffer.from('{"mode":"block"}\n');
    const originalWorkspace = Buffer.from(
      '{"folders":[],"settings":{"window.title":"QA"}}\n',
    );
    const activeSettings = Buffer.from('{"http.proxy":"loopback"}\n');
    const activeConfig = Buffer.from('{"mode":"block","apiUrl":"loopback"}\n');
    const unexpectedConfig = Buffer.from(
      '{"mode":"allow","apiUrl":"loopback"}\n',
    );
    const observedSettings = Buffer.from(
      '{"http.proxy":"loopback","chat.disableAIFeatures":true}\n',
    );
    const observedWorkspace = Buffer.from(
      '{"folders":[],"settings":{"window.title":"QA","chat.disableAIFeatures":false}}\n',
    );
    const observation = await inspectAndArchiveFreshUiFiles({
      activeSettingsBytes: activeSettings,
      activeConfigBytes: activeConfig,
      originalWorkspaceBytes: originalWorkspace,
      observedSettingsBytes: observedSettings,
      observedConfigBytes: unexpectedConfig,
      observedWorkspaceBytes: observedWorkspace,
      archiveDirectory,
    });
    assert.equal(observation.classification.expected, false);
    assert.equal(observation.classification.config.state, "unexpected");
    const configArchive = observation.archives.config;
    assert.ok(configArchive);
    assert.deepEqual(
      await readFile(configArchive.path),
      unexpectedConfig,
    );

    await Promise.all([
      writeFile(settingsPath, observedSettings),
      writeFile(configPath, unexpectedConfig),
      writeFile(workspacePath, observedWorkspace),
    ]);
    const restored = await restoreFreshProfileFiles({
      ownedProfileRoot: temporary,
      settingsPath,
      settingsBytes: originalSettings,
      configPath,
      configBytes: originalConfig,
      workspaceFilePath: workspacePath,
      workspaceFileBytes: originalWorkspace,
    });
    assert.equal(restored.byteExact, true);
    assert.deepEqual(await readFile(settingsPath), originalSettings);
    assert.deepEqual(await readFile(configPath), originalConfig);
    assert.deepEqual(await readFile(workspacePath), originalWorkspace);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

for (const rejectedName of ["settings", "workspace"] as const) {
  test(`restoration rejects an external ${rejectedName} symlink before any write`, async () => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), "svqa-restore-"));
    try {
      const profileRoot = path.join(temporary, "profile");
      await mkdir(profileRoot, { mode: 0o700 });
      const settingsPath = path.join(profileRoot, "settings.json");
      const configPath = path.join(profileRoot, "config.json");
      const workspacePath = path.join(profileRoot, "native.code-workspace");
      const activeSettings = Buffer.from('{"http.proxy":"active"}\n');
      const activeConfig = Buffer.from('{"apiUrl":"active"}\n');
      const activeWorkspace = Buffer.from('{"settings":{"window.title":"active"}}\n');
      const originalSettings = Buffer.from('{"http.proxy":"original"}\n');
      const originalConfig = Buffer.from('{"apiUrl":"original"}\n');
      const originalWorkspace = Buffer.from(
        '{"settings":{"window.title":"original"}}\n',
      );
      await Promise.all([
        writeFile(settingsPath, activeSettings),
        writeFile(configPath, activeConfig),
        writeFile(workspacePath, activeWorkspace),
      ]);
      const rejectedPath =
        rejectedName === "settings" ? settingsPath : workspacePath;
      const externalPath = path.join(
        temporary,
        `${rejectedName}-external.json`,
      );
      const externalBytes = Buffer.from('{"external":"must-not-change"}\n');
      await writeFile(externalPath, externalBytes);
      await unlink(rejectedPath);
      await symlink(externalPath, rejectedPath);

      await assert.rejects(
        restoreFreshProfileFiles({
          ownedProfileRoot: profileRoot,
          settingsPath,
          settingsBytes: originalSettings,
          configPath,
          configBytes: originalConfig,
          workspaceFilePath: workspacePath,
          workspaceFileBytes: originalWorkspace,
        }),
        /must not be a symlink/u,
      );
      assert.deepEqual(await readFile(externalPath), externalBytes);
      assert.equal((await lstat(rejectedPath)).isSymbolicLink(), true);
      assert.equal(await readlink(rejectedPath), externalPath);
      assert.deepEqual(await readFile(configPath), activeConfig);
      if (rejectedName === "settings") {
        assert.deepEqual(await readFile(workspacePath), activeWorkspace);
      } else {
        assert.deepEqual(await readFile(settingsPath), activeSettings);
      }
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  });
}

test("post-pass restoration failure writes a failed receipt and rejects", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svqa-outcome-"));
  try {
    const receiptPath = path.join(temporary, "receipt.json");
    const receipt = { schemaVersion: 1, result: "pass" };
    const restorationError = new Error("synthetic restoration failure");
    await assert.rejects(
      writeFinalQualificationReceipt({
        receiptPath,
        receipt,
        failure: restorationError,
        ownedServersClosed: true,
        ownedProcessSettled: true,
      }),
      restorationError,
    );
    const stored = JSON.parse(await readFile(receiptPath, "utf8"));
    assert.equal(stored.result, "fail");
    assert.equal(stored.error.message, restorationError.message);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

for (const cleanupCase of [
  {
    name: "owned server cleanup",
    ownedServersClosed: false,
    ownedProcessSettled: true,
    message: "owned loopback servers failed to close",
  },
  {
    name: "owned process settlement",
    ownedServersClosed: true,
    ownedProcessSettled: false,
    message: "owned VS Code process did not reach a settled exit",
  },
]) {
  test(`${cleanupCase.name} failure forces a failed receipt`, async () => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), "svqa-outcome-"));
    try {
      const receiptPath = path.join(temporary, "receipt.json");
      const receipt = { schemaVersion: 1, result: "pass" };
      await assert.rejects(
        writeFinalQualificationReceipt({
          receiptPath,
          receipt,
          ownedServersClosed: cleanupCase.ownedServersClosed,
          ownedProcessSettled: cleanupCase.ownedProcessSettled,
        }),
        new RegExp(cleanupCase.message, "u"),
      );
      const stored = JSON.parse(await readFile(receiptPath, "utf8"));
      assert.equal(stored.result, "fail");
      assert.match(stored.finalizationErrors[0].message, /owned/u);
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  });
}

test("normal settled cleanup preserves a passing receipt", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svqa-outcome-"));
  try {
    const receiptPath = path.join(temporary, "receipt.json");
    const receipt = { schemaVersion: 1, result: "pass" };
    const result = await writeFinalQualificationReceipt({
      receiptPath,
      receipt,
      ownedServersClosed: true,
      ownedProcessSettled: true,
    });
    assert.equal(result.result, "pass");
    assert.equal(
      JSON.parse(await readFile(receiptPath, "utf8")).result,
      "pass",
    );
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("non-native preflight statuses are preserved only without a launch receipt", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svqa-outcome-"));
  try {
    for (const status of ["source-pass", "unsupported"] as const) {
      const receiptPath = path.join(temporary, `${status}.json`);
      const receipt = {
        schemaVersion: 1,
        result: status,
        process: {},
      };
      const result = await writeFinalQualificationReceipt({
        receiptPath,
        receipt,
        ownedServersClosed: true,
        ownedProcessSettled: true,
      });
      assert.equal(result.result, status);
      assert.equal(
        JSON.parse(await readFile(receiptPath, "utf8")).result,
        status,
      );
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("non-native preflight statuses reject every recorded PID value", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svqa-outcome-"));
  try {
    for (const status of ["source-pass", "unsupported"] as const) {
      for (const [name, pid] of [
        ["valid", 42],
        ["null", null],
        ["malformed", "not-a-pid"],
      ] as const) {
        const receiptPath = path.join(temporary, `${status}-${name}.json`);
        const receipt = {
          schemaVersion: 1,
          result: status,
          process: { pid },
        };
        await assert.rejects(
          writeFinalQualificationReceipt({
            receiptPath,
            receipt,
            ownedServersClosed: true,
            ownedProcessSettled: true,
          }),
          new RegExp(`ended with result ${status}`, "u"),
        );
        assert.equal(
          JSON.parse(await readFile(receiptPath, "utf8")).result,
          "fail",
        );
      }
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("cleanup failures override accepted non-native preflight statuses", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svqa-outcome-"));
  try {
    for (const cleanupCase of [
      {
        status: "source-pass",
        ownedServersClosed: false,
        ownedProcessSettled: true,
        message: /owned loopback servers failed to close/u,
      },
      {
        status: "unsupported",
        ownedServersClosed: true,
        ownedProcessSettled: false,
        message: /owned VS Code process did not reach a settled exit/u,
      },
    ] as const) {
      const receiptPath = path.join(
        temporary,
        `${cleanupCase.status}-cleanup.json`,
      );
      const receipt = {
        schemaVersion: 1,
        result: cleanupCase.status,
        process: {},
      };
      await assert.rejects(
        writeFinalQualificationReceipt({
          receiptPath,
          receipt,
          ownedServersClosed: cleanupCase.ownedServersClosed,
          ownedProcessSettled: cleanupCase.ownedProcessSettled,
        }),
        cleanupCase.message,
      );
      const stored = JSON.parse(await readFile(receiptPath, "utf8"));
      assert.equal(stored.result, "fail");
      assert.equal(stored.finalizationErrors.length, 1);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("fresh human mode waits for normal UI trust without bypassing trust", () => {
  assert.equal(workspaceTrustAction({
    workspaceTrusted: false,
    allowNormalTrustHandoff: true,
  }), "wait-for-normal-ui-trust");
  assert.throws(() => workspaceTrustAction({
    workspaceTrusted: false,
    allowNormalTrustHandoff: false,
  }), /strict QA stopped without prompting/u);
  assert.equal(workspaceTrustAction({
    workspaceTrusted: true,
    allowNormalTrustHandoff: false,
  }), "continue");
});

test("portable launcher has one launch site behind the strict preflight return", async () => {
  const launcher = await readFile(new URL(
    "../scripts/vscode-native-qualification.mjs",
    import.meta.url,
  ), "utf8");
  assert.equal(
    launcher.match(/receipt\.process = await launchApp\(/gu)?.length,
    1,
  );
  const toolManifestPreflight = launcher.indexOf(
    "receipt.source.qaToolManifest = validateQaToolManifest(",
  );
  const preflightReturn = launcher.indexOf("if (!policy.allowLaunch)");
  const launch = launcher.indexOf("receipt.process = await launchApp(");
  assert.ok(
    toolManifestPreflight > 0
      && toolManifestPreflight < preflightReturn
      && preflightReturn < launch,
  );
});

test("cleanup stops only the exact owned detached process group", async () => {
  let child: ReturnType<typeof spawn> | undefined;
  let closed: Promise<unknown[]> | undefined;
  let testError: unknown;
  try {
    child = spawn(process.execPath, [
      "-e",
      "setInterval(() => {}, 1_000)",
    ], {
      detached: true,
      stdio: "ignore",
    });
    await once(child, "spawn");
    assert.equal(typeof child.pid, "number");
    const identity = await waitForOwnedProcessGroup(child.pid!);
    assert.deepEqual(identity, {
      pid: child.pid,
      processGroupId: child.pid,
    });
    closed = once(child, "close");
    await terminateOwnedProcessGroup(identity.pid);
    await closed;
    assert.equal(await ownedProcessGroupExists(identity.pid), false);
  } catch (error) {
    testError = error;
    throw error;
  } finally {
    try {
      if (
        child?.pid
        && child.exitCode === null
        && child.signalCode === null
      ) {
        child.kill("SIGKILL");
        closed ??= once(child, "close");
        await closed;
      }
    } catch (cleanupError) {
      if (testError === undefined) throw cleanupError;
    }
  }
});

test("incremental journal survives bounded termination of a hanging non-GUI child", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svqa-journal-child-"));
  const journalPath = path.join(temporary, "provider-tool.ndjson");
  const readyPath = path.join(temporary, "ready");
  const capturePath = path.join(temporary, "provider-capture.json");
  const helperPath = fileURLToPath(new URL(
    "../qa/vscode-native/extension/provider-journal.cjs",
    import.meta.url,
  ));
  let child: ReturnType<typeof spawn> | undefined;
  let closed: Promise<unknown[]> | undefined;
  try {
    child = spawn(process.execPath, [
      "-e",
      [
        "const fs = require('node:fs');",
        "const { createProviderJournal } = require(process.argv[1]);",
        "(async () => {",
        "  const journal = await createProviderJournal(process.argv[2]);",
        "  await journal.append({",
        "    type: 'provider-request',",
        "    providerSequence: 1,",
        "    request: { sequence: 1, messages: [{ content: 'synthetic title' }] },",
        "  });",
        "  await journal.append({",
        "    type: 'tool-invocation',",
        "    toolName: 'silmaril_native_qa_posttool_8d724ae7',",
        "    invocationCount: 1,",
        "  });",
        "  fs.writeFileSync(process.argv[3], 'ready\\n', { mode: 0o600 });",
        "  setInterval(() => {}, 1_000);",
        "})().catch((error) => { console.error(error); process.exit(1); });",
      ].join("\n"),
      helperPath,
      journalPath,
      readyPath,
    ], {
      detached: true,
      stdio: "ignore",
    });
    await once(child, "spawn");
    const identity = await waitForOwnedProcessGroup(child.pid!);
    const deadline = Date.now() + 2_000;
    while (Date.now() < deadline) {
      if (await readFile(readyPath, "utf8").then(
        () => true,
        (error: NodeJS.ErrnoException) => {
          if (error.code === "ENOENT") return false;
          throw error;
        },
      )) break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.equal(await readFile(readyPath, "utf8"), "ready\n");
    closed = once(child, "close");
    await terminateOwnedProcessGroup(identity.pid);
    await closed;

    const journal = await inspectProviderJournal(journalPath);
    assert.equal(journal.integrity, "pass");
    assert.equal(journal.validRecordCount, 2);
    assert.ok(journal.records.every((record) =>
      record.state === "in-progress"
      && record.completion === "not-finished"));
    await assert.rejects(
      readFile(capturePath),
      (error: NodeJS.ErrnoException) => error.code === "ENOENT",
      "Incremental records must not fabricate a finished suite capture",
    );
  } finally {
    if (
      child?.pid
      && await ownedProcessGroupExists(child.pid).catch(() => false)
    ) {
      await terminateOwnedProcessGroup(child.pid);
      closed ??= once(child, "close");
      await closed;
    }
    await rm(temporary, { recursive: true, force: true });
  }
});

test("owned helper outliving its leader is removed before restoration", async () => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "svqa-group-"));
  const helperReadyPath = path.join(temporary, "helper-ready");
  let leader: ReturnType<typeof spawn> | undefined;
  try {
    leader = spawn(process.execPath, [
      "-e",
      [
        "const fs = require('node:fs');",
        "const { spawn } = require('node:child_process');",
        "const helper = spawn(process.execPath, [",
        "  '-e',",
        "  'process.on(\"SIGTERM\", () => {}); setInterval(() => {}, 1000)',",
        "], { stdio: 'ignore' });",
        "fs.writeFileSync(process.argv[1], String(helper.pid), { mode: 0o600 });",
        "setTimeout(() => process.exit(0), 300);",
      ].join("\n"),
      helperReadyPath,
    ], {
      detached: true,
      stdio: "ignore",
    });
    await once(leader, "spawn");
    const leaderClosed = once(leader, "close");
    const identity = await waitForOwnedProcessGroup(leader.pid!);
    await leaderClosed;
    assert.equal(await ownedProcessGroupExists(identity.pid), true);

    const cleanup = await settleOwnedProcessGroup({
      pid: identity.pid,
      processGroupIdentity: identity,
      code: 0,
    });
    assert.equal(cleanup.presentBeforeCleanup, true);
    assert.equal(cleanup.terminationAttempted, true);
    assert.equal(cleanup.groupAbsent, true);

    const profileRoot = path.join(temporary, "profile");
    await mkdir(profileRoot, { mode: 0o700 });
    const settingsPath = path.join(profileRoot, "settings.json");
    const configPath = path.join(profileRoot, "config.json");
    const workspacePath = path.join(profileRoot, "native.code-workspace");
    await Promise.all([
      writeFile(settingsPath, "changed-settings", { mode: 0o600 }),
      writeFile(configPath, "changed-config", { mode: 0o600 }),
      writeFile(workspacePath, "changed-workspace", { mode: 0o600 }),
    ]);
    const restoration = await restoreFreshProfileFiles({
      ownedProfileRoot: profileRoot,
      settingsPath,
      settingsBytes: Buffer.from("original-settings"),
      configPath,
      configBytes: Buffer.from("original-config"),
      workspaceFilePath: workspacePath,
      workspaceFileBytes: Buffer.from("original-workspace"),
    });
    assert.equal(restoration.byteExact, true);
  } finally {
    if (
      leader?.pid
      && await ownedProcessGroupExists(leader.pid).catch(() => false)
    ) {
      await terminateOwnedProcessGroup(leader.pid);
    }
    await rm(temporary, { recursive: true, force: true });
  }
});

test("group inspection or termination uncertainty rejects cleanup", async () => {
  for (const pid of [null, undefined, "42", 0, 1, 1.5]) {
    await assert.rejects(
      settleOwnedProcessGroup({ pid } as any),
      /Recorded owned process-group PID is invalid/u,
    );
  }
  const receipt = {
    pid: 42,
    processGroupIdentity: { pid: 42, processGroupId: 42 },
    code: 0,
  };
  await assert.rejects(
    settleOwnedProcessGroup(receipt, {
      groupExists: async () => {
        throw new Error("synthetic group inspection failure");
      },
    }),
    /synthetic group inspection failure/u,
  );
  await assert.rejects(
    settleOwnedProcessGroup(receipt, {
      groupExists: async () => true,
      terminateGroup: async () => {
        throw new Error("synthetic group termination failure");
      },
    }),
    (error: Error & { processGroupCleanup?: Record<string, any> }) => {
      assert.match(error.message, /synthetic group termination failure/u);
      assert.equal(
        error.processGroupCleanup?.terminationAttempted,
        true,
      );
      assert.equal(error.processGroupCleanup?.groupAbsent, false);
      return true;
    },
  );
  const launcher = await readFile(new URL(
    "../scripts/vscode-native-qualification.mjs",
    import.meta.url,
  ), "utf8");
  assert.ok(
    launcher.indexOf("receipt.processGroupCleanup = await settleOwnedProcessGroup(")
      < launcher.indexOf("if (freshRestore && receipt.ownedProcessSettled)"),
  );
  assert.match(
    launcher,
    /else if \(freshRestore\) \{[\s\S]*restorationSkipped:/u,
    "Unproven group absence must skip restoration writes",
  );
});

test("loopback CONNECT and classifier sockets close through the bounded cleanup", async () => {
  let upstreamSocket: net.Socket | undefined;
  const upstreamServer = net.createServer((socket) => {
    upstreamSocket = socket;
  });
  await new Promise<void>((resolve, reject) => {
    upstreamServer.once("error", reject);
    upstreamServer.listen(0, "127.0.0.1", () => resolve());
  });
  const upstreamAddress = upstreamServer.address();
  assert.ok(upstreamAddress && typeof upstreamAddress === "object");

  const proxy = startDestinationProxy({
    connectFactory({ host, port }) {
      assert.deepEqual({ host, port }, { host: "api.github.com", port: 443 });
      return net.connect(upstreamAddress.port, "127.0.0.1");
    },
  });
  const proxyUrl = new URL(await proxy.open());
  const client = net.connect(Number(proxyUrl.port), "127.0.0.1");
  await once(client, "connect");
  client.write(
    "CONNECT api.github.com:443 HTTP/1.1\r\n"
      + "Host: api.github.com:443\r\n\r\n",
  );
  const [response] = await once(client, "data") as [Buffer];
  assert.match(response.toString("utf8"), /200 Connection Established/u);
  assert.ok(upstreamSocket && !upstreamSocket.destroyed);
  client.on("error", () => {});
  upstreamSocket.on("error", () => {});
  const clientClosed = new Promise<void>((resolve) => {
    client.once("close", () => resolve());
  });
  const upstreamClosed = new Promise<void>((resolve) => {
    upstreamSocket!.once("close", () => resolve());
  });
  await proxy.close();
  await Promise.all([clientClosed, upstreamClosed]);
  assert.equal(client.destroyed, true);
  assert.equal(upstreamSocket.destroyed, true);
  await new Promise<void>((resolve, reject) => {
    upstreamServer.close((error) => error ? reject(error) : resolve());
  });

  const classifier = startClassifier();
  const classifierUrl = new URL(await classifier.open());
  const incompleteClient = net.connect(
    Number(classifierUrl.port),
    "127.0.0.1",
  );
  await once(incompleteClient, "connect");
  incompleteClient.on("error", () => {});
  incompleteClient.write(
    "POST /classify HTTP/1.1\r\n"
      + "Host: 127.0.0.1\r\nContent-Length: 100\r\n\r\n{}",
  );
  const incompleteClosed = new Promise<void>((resolve) => {
    incompleteClient.once("close", () => resolve());
  });
  await classifier.close();
  await incompleteClosed;
  assert.equal(incompleteClient.destroyed, true);
});

test("owned server close rejects when its callback never settles", async () => {
  const started = Date.now();
  await assert.rejects(
    closeServer({
      close() {},
      closeAllConnections() {},
    }, new Set(), 30),
    /Timed out after 30ms/u,
  );
  assert.ok(Date.now() - started < 1_000);
});
