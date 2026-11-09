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
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  buildMinimalChildEnvironment,
  buildNativeLaunchArgs,
  byteReceipt,
  collectStrings,
  createQualificationCoverage,
  createFreshQaLayout,
  inspectSecretStorageIsolation,
  inspectSecretStorageRuntimeLogs,
  inspectAndArchiveFreshUiFiles,
  inspectNativeCjsMissingIdentifiers,
  inspectNormalUiAgentEnablement,
  inspectSourceContracts,
  ownedProcessGroupExists,
  resolvePortableQaPolicy,
  restoreFreshProfileFiles,
  terminateOwnedProcessGroup,
  validateQaToolManifest,
  validateSharedCallbackRoutes,
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
const { classifyFreshProfileUiFiles } = require(
  "../qa/vscode-native/extension/agent-ui-policy.cjs",
) as {
  classifyFreshProfileUiFiles(options: Record<string, Uint8Array>): {
    expected: boolean;
    expectedUiTransitionObserved: boolean;
    phaseOrderValid: boolean;
    settings: { state: string };
    config: { state: string };
    workspace: { state: string };
  };
};
const { snapshotNativeState } = require(
  "../qa/vscode-native/extension/capture-state.cjs",
) as {
  snapshotNativeState(
    receipt: Record<string, any>,
    nativeState: Record<string, any> | undefined,
  ): Record<string, any>;
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
  assert.match(
    launcher,
    /if \(!policy\.allowLaunch\) \{\s+receipt\.result = "source-pass";\s+return receipt;\s+\}\s+receipt\.resultScope = "four-case-native-core";\s+receipt\.coverage\.nativeCore\.result = "fail";/u,
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

test("prelaunch CJS oracle catches a missing suite import without touching disk", async () => {
  assert.deepEqual(inspectNativeCjsMissingIdentifiers(), []);
  const suitePath = fileURLToPath(new URL(
    "../qa/vscode-native/extension/suite.cjs",
    import.meta.url,
  ));
  const suite = await readFile(suitePath, "utf8");
  const mutated = suite.replace(
    "  classifyExactSettingDelta,\n  sha256Bytes,\n",
    "  classifyExactSettingDelta,\n",
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
    allowLaunch: false,
    allowNormalTrustHandoff: false,
    allowUiEnableHandoff: false,
    handoffs: {
      trust: undefined,
      disableAi: undefined,
      workspaceAi: undefined,
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
      NATIVE_TRUST_PENDING_PATH: path.join(root, "handoffs", "trust.json"),
      NATIVE_AGENT_ENABLE_PENDING_PATH:
        path.join(root, "handoffs", "disable.json"),
      NATIVE_WORKSPACE_AI_ENABLE_PENDING_PATH:
        path.join(root, "handoffs", "workspace.json"),
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
      NATIVE_TRUST_PENDING_PATH: collisionReceipt,
      NATIVE_AGENT_ENABLE_PENDING_PATH:
        path.join(collisionRoot, "disable.json"),
      NATIVE_WORKSPACE_AI_ENABLE_PENDING_PATH:
        path.join(collisionRoot, "workspace.json"),
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

test("two-phase UI deltas are exact and preserve every unrelated field", () => {
  const activeSettings = Buffer.from(JSON.stringify({
    "http.proxy": "http://127.0.0.1:2001",
    "chat.allowAnonymousAccess": true,
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
