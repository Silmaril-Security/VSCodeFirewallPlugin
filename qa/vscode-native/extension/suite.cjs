"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const vscode = require("vscode");
const {
  AI_SETTING,
  classifyExactSettingDelta,
  sha256Bytes,
} = require("./agent-ui-policy.cjs");
const { snapshotNativeState } = require("./capture-state.cjs");
const { buildSafeExtensionInventory } = require("./inventory.cjs");
const {
  SHARED_COPILOT_ROUTE,
  modelSelectorForRoute,
  modelSelectorFromPublicModel,
  readFreshProfileTurnRows,
  validateFirstSharedTurnRows,
  validateSelectionActionAttestation,
  validateWrappedModels,
} = require("./shared-route-policy.cjs");
const { workspaceTrustAction } = require("./trust-policy.cjs");

const ALLOW_QUERY =
  " \tSILMARIL_NATIVE_ALLOW_8d724ae7 exact transformed bytes β\r\n ";
const BLOCK_QUERY =
  "SILMARIL_NATIVE_BLOCK_8d724ae7 must not reach the dummy provider";
const PRE_QUERY =
  "SILMARIL_NATIVE_PREBLOCK_8d724ae7 request the private synthetic tool once";
const POST_QUERY =
  "SILMARIL_NATIVE_POSTTOOL_8d724ae7 request the private poison tool once";

async function writeCapture(capturePath, value) {
  await fs.mkdir(path.dirname(capturePath), { recursive: true, mode: 0o700 });
  await fs.writeFile(capturePath, `${JSON.stringify(value, null, 2)}\n`, {
    mode: 0o600,
  });
}

async function writeImmutableCapture(capturePath, value) {
  await fs.mkdir(path.dirname(capturePath), { recursive: true, mode: 0o700 });
  await fs.writeFile(capturePath, `${JSON.stringify(value, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
}

async function sha256File(filePath) {
  return createHash("sha256")
    .update(await fs.readFile(filePath))
    .digest("hex");
}

function extensionInventoryCapture() {
  const extensions = buildSafeExtensionInventory(vscode.extensions.all);
  return {
    schemaVersion: 1,
    capturedAt: new Date().toISOString(),
    source: "vscode.extensions.all",
    publicRunningLocationAvailable: false,
    count: extensions.length,
    copilotChatMatches: extensions.filter(
      (extension) => extension.id === "github.copilot-chat",
    ).length,
    extensions,
  };
}

async function verifyOrdinaryBuiltInCopilot(copilot) {
  const expectedPath = process.env.SILMARIL_NATIVE_EXPECTED_COPILOT_PATH;
  const expectedVersion =
    process.env.SILMARIL_NATIVE_EXPECTED_COPILOT_VERSION;
  const expectedManifestSha256 =
    process.env.SILMARIL_NATIVE_EXPECTED_COPILOT_MANIFEST_SHA256;
  const expectedSourceSha256 =
    process.env.SILMARIL_NATIVE_EXPECTED_COPILOT_SOURCE_SHA256;
  assert.ok(expectedPath && path.isAbsolute(expectedPath));
  assert.equal(copilot.id.toLowerCase(), "github.copilot-chat");
  assert.equal(copilot.packageJSON.version, expectedVersion);
  assert.equal(copilot.packageJSON.isBuiltin, true);
  assert.equal(copilot.extensionUri.scheme, "file");
  assert.equal(
    await fs.realpath(copilot.extensionUri.fsPath),
    await fs.realpath(expectedPath),
    "Copilot did not register from the exact signed built-in location",
  );
  assert.equal(
    await sha256File(path.join(expectedPath, "package.json")),
    expectedManifestSha256,
    "Registered Copilot manifest differs from the reviewed signed app",
  );
  assert.equal(
    await sha256File(path.join(expectedPath, "dist", "extension.js")),
    expectedSourceSha256,
    "Registered Copilot source differs from the reviewed signed app",
  );
  return {
    id: copilot.id,
    version: copilot.packageJSON.version,
    isBuiltin: true,
    location: {
      scheme: copilot.extensionUri.scheme,
      basename: path.basename(copilot.extensionUri.fsPath),
    },
    manifestSha256: expectedManifestSha256,
    sourceSha256: expectedSourceSha256,
  };
}

function aiConfigurationCapture() {
  const configuration = vscode.workspace.getConfiguration("chat");
  const inspected = configuration.inspect("disableAIFeatures");
  assert.ok(inspected, `Unable to inspect ${AI_SETTING}`);
  const value = (candidate) =>
    typeof candidate === "boolean" ? candidate : null;
  return {
    source: "vscode.workspace.getConfiguration().inspect()",
    key: AI_SETTING,
    effectiveValue: value(configuration.get("disableAIFeatures")),
    defaultValue: value(inspected.defaultValue),
    globalValue: value(inspected.globalValue),
    workspaceValue: value(inspected.workspaceValue),
    workspaceFolderValue: value(inspected.workspaceFolderValue),
  };
}

async function readUiStateFiles() {
  const profileSettingsPath =
    process.env.SILMARIL_NATIVE_PROFILE_SETTINGS_PATH;
  const workspaceFilePath =
    process.env.SILMARIL_NATIVE_WORKSPACE_FILE_PATH;
  assert.ok(
    profileSettingsPath && path.isAbsolute(profileSettingsPath),
    "Missing private profile-settings path",
  );
  assert.ok(
    workspaceFilePath && path.isAbsolute(workspaceFilePath),
    "Missing owned workspace-file path",
  );
  return {
    profileSettingsPath,
    workspaceFilePath,
    profileSettingsBytes: await fs.readFile(profileSettingsPath),
    workspaceFileBytes: await fs.readFile(workspaceFilePath),
  };
}

function assertExpectedUiDelta(proof, description) {
  assert.equal(
    proof.state,
    "expected-ui-delta",
    `${description} was not the one exact approved ${AI_SETTING} delta`,
  );
}

async function waitForConfigurationValue(expectedValue, timeoutMs) {
  const current = aiConfigurationCapture();
  if (current.effectiveValue === expectedValue) return current;
  return await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      listener.dispose();
      reject(new Error(
        `Timed out waiting for public ${AI_SETTING}=${expectedValue} configuration event`,
      ));
    }, timeoutMs);
    const listener = vscode.workspace.onDidChangeConfiguration((event) => {
      if (!event.affectsConfiguration(AI_SETTING)) return;
      try {
        const capture = aiConfigurationCapture();
        if (capture.effectiveValue !== expectedValue) return;
        clearTimeout(timeout);
        listener.dispose();
        resolve(capture);
      } catch (error) {
        clearTimeout(timeout);
        listener.dispose();
        reject(error);
      }
    });
  });
}

async function waitForExactFileDelta(read, classify, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let proof;
  do {
    proof = classify(await read());
    if (proof.state === "expected-ui-delta") return proof;
    await new Promise((resolve) => setTimeout(resolve, 50));
  } while (Date.now() < deadline);
  return proof;
}

async function waitForNormalUiAgentEnablement(currentInventory) {
  const disableReadyPath =
    process.env.SILMARIL_NATIVE_AI_DISABLE_READY_PATH;
  const workspaceEnableReadyPath =
    process.env.SILMARIL_NATIVE_AI_WORKSPACE_ENABLE_READY_PATH;
  assert.ok(
    disableReadyPath && path.isAbsolute(disableReadyPath),
    "Missing normal-UI Disable AI Features ready path",
  );
  assert.ok(
    workspaceEnableReadyPath && path.isAbsolute(workspaceEnableReadyPath),
    "Missing normal-UI workspace AI enable ready path",
  );
  assert.notEqual(disableReadyPath, workspaceEnableReadyPath);
  const expectedPath = process.env.SILMARIL_NATIVE_EXPECTED_COPILOT_PATH;
  const expectedVersion =
    process.env.SILMARIL_NATIVE_EXPECTED_COPILOT_VERSION;
  assert.equal(
    vscode.workspace.isTrusted,
    true,
    "Normal-UI agent enablement cannot start before normal workspace trust",
  );
  assert.ok(expectedPath && path.isAbsolute(expectedPath));
  assert.ok(expectedVersion);
  assert.equal(
    currentInventory.copilotChatMatches,
    0,
    "Two-phase normal UI handoff is valid only while Copilot is absent",
  );
  const beforeFiles = await readUiStateFiles();
  const beforeConfiguration = aiConfigurationCapture();
  assert.equal(
    beforeConfiguration.effectiveValue,
    false,
    `Two-phase handoff requires initial ${AI_SETTING}=false`,
  );
  assert.equal(
    beforeConfiguration.workspaceValue,
    null,
    `Two-phase handoff requires no pre-existing workspace ${AI_SETTING}`,
  );

  const phaseOneWait = waitForConfigurationValue(true, 180_000);
  await writeImmutableCapture(disableReadyPath, {
    schemaVersion: 1,
    state: "normal-ui-disable-ai-required",
    phase: 1,
    readyAt: new Date().toISOString(),
    vscodeVersion: vscode.version,
    appName: vscode.env.appName,
    windowTitle: process.env.SILMARIL_NATIVE_WINDOW_TITLE,
    workspaceTrusted: vscode.workspace.isTrusted,
    before: {
      configuration: beforeConfiguration,
      inventory: currentInventory,
      profileSettingsSha256: sha256Bytes(
        beforeFiles.profileSettingsBytes,
      ),
      workspaceFileSha256: sha256Bytes(beforeFiles.workspaceFileBytes),
    },
    normalUiAction: {
      surface: "Extensions view",
      actionIdFromSignedSource: "extensions.disableAIGlobally",
      actionLabel: "Disable AI Features",
      accountOrInstallPermitted: false,
    },
  });
  const intermediateConfiguration = await phaseOneWait;
  assert.equal(
    intermediateConfiguration.globalValue,
    true,
    `Disable AI Features did not write private-profile ${AI_SETTING}=true`,
  );
  const profileDelta = await waitForExactFileDelta(
    () => fs.readFile(beforeFiles.profileSettingsPath),
    (observedBytes) => classifyExactSettingDelta({
      baselineBytes: beforeFiles.profileSettingsBytes,
      observedBytes,
      value: true,
      description: "private profile settings",
    }),
    10_000,
  );
  assertExpectedUiDelta(profileDelta, "Private profile settings");
  const workspaceAfterPhaseOne = await fs.readFile(
    beforeFiles.workspaceFilePath,
  );
  assert.deepEqual(
    workspaceAfterPhaseOne,
    beforeFiles.workspaceFileBytes,
    "Disable AI Features changed the workspace file before phase 2",
  );

  let listener;
  let timeout;
  const extensionWait = new Promise((resolve, reject) => {
    const inspect = async () => {
      const extension = vscode.extensions.getExtension("github.copilot-chat");
      if (!extension) return;
      try {
        const proof = await verifyOrdinaryBuiltInCopilot(extension);
        clearTimeout(timeout);
        listener.dispose();
        resolve({ extension, proof });
      } catch (error) {
        clearTimeout(timeout);
        listener.dispose();
        reject(error);
      }
    };
    listener = vscode.extensions.onDidChange(() => {
      inspect().catch(reject);
    });
    timeout = setTimeout(() => {
      listener.dispose();
      reject(new Error(
        "Timed out waiting for normal UI enablement of exact built-in GitHub Copilot Chat",
      ));
    }, 180_000);
    inspect().catch(reject);
  });
  await writeImmutableCapture(workspaceEnableReadyPath, {
    schemaVersion: 1,
    state: "normal-ui-workspace-ai-enable-required",
    phase: 2,
    readyAt: new Date().toISOString(),
    vscodeVersion: vscode.version,
    appName: vscode.env.appName,
    windowTitle: process.env.SILMARIL_NATIVE_WINDOW_TITLE,
    workspaceTrusted: vscode.workspace.isTrusted,
    requiredExtension: {
      id: "github.copilot-chat",
      version: expectedVersion,
      isBuiltin: true,
      signedLocationBasename: path.basename(expectedPath),
      manifestSha256:
        process.env.SILMARIL_NATIVE_EXPECTED_COPILOT_MANIFEST_SHA256,
      sourceSha256:
        process.env.SILMARIL_NATIVE_EXPECTED_COPILOT_SOURCE_SHA256,
    },
    normalUiAction: {
      surface: "Extensions view",
      actionIdFromSignedSource: "extensions.enableAIInWorkspace",
      actionLabel: "Enable AI Features (Workspace)",
      accountOrInstallPermitted: false,
    },
    intermediate: {
      configuration: intermediateConfiguration,
      profileSettingsDelta: profileDelta,
      workspaceFileSha256: sha256Bytes(workspaceAfterPhaseOne),
      currentInventory: extensionInventoryCapture(),
    },
  });
  const enabled = await extensionWait;
  const afterConfiguration = await waitForConfigurationValue(false, 10_000);
  assert.equal(
    afterConfiguration.workspaceValue,
    false,
    `Enable AI Features (Workspace) did not write workspace ${AI_SETTING}=false`,
  );
  const afterFiles = await readUiStateFiles();
  const finalProfileDelta = classifyExactSettingDelta({
    baselineBytes: beforeFiles.profileSettingsBytes,
    observedBytes: afterFiles.profileSettingsBytes,
    value: true,
    description: "private profile settings",
  });
  assertExpectedUiDelta(finalProfileDelta, "Private profile settings");
  const workspaceDelta = await waitForExactFileDelta(
    () => fs.readFile(beforeFiles.workspaceFilePath),
    (observedBytes) => classifyExactSettingDelta({
      baselineBytes: beforeFiles.workspaceFileBytes,
      observedBytes,
      container: "settings",
      value: false,
      description: "owned workspace file",
    }),
    10_000,
  );
  assertExpectedUiDelta(workspaceDelta, "Owned workspace file");
  return {
    ...enabled,
    phases: {
      before: {
        configuration: beforeConfiguration,
        profileSettingsSha256: sha256Bytes(
          beforeFiles.profileSettingsBytes,
        ),
        workspaceFileSha256: sha256Bytes(beforeFiles.workspaceFileBytes),
      },
      intermediate: {
        markerPath: disableReadyPath,
        configuration: intermediateConfiguration,
        profileSettingsDelta: profileDelta,
        workspaceFileSha256: sha256Bytes(workspaceAfterPhaseOne),
      },
      after: {
        markerPath: workspaceEnableReadyPath,
        configuration: afterConfiguration,
        profileSettingsDelta: finalProfileDelta,
        workspaceFileDelta: workspaceDelta,
      },
    },
  };
}

async function readPrivateDeviceId() {
  const userData = process.env.SILMARIL_NATIVE_USER_DATA;
  assert.ok(
    userData && path.isAbsolute(userData),
    "Missing private user-data path",
  );
  const storagePath = path.join(
    userData,
    "User",
    "globalStorage",
    "storage.json",
  );
  const storage = JSON.parse(await fs.readFile(storagePath, "utf8"));
  const deviceId = storage["telemetry.devDeviceId"];
  assert.match(
    deviceId,
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    "Private profile does not contain a UUID device ID",
  );
  return deviceId;
}

async function readPrivateLogs(root, excludedRootEntries) {
  const logs = [];
  async function visit(directory) {
    let entries;
    try {
      entries = await fs.readdir(directory, { withFileTypes: true });
    } catch (error) {
      if (error?.code === "ENOENT") return;
      throw error;
    }
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(absolute);
      } else if (entry.isFile() && entry.name.endsWith(".log")) {
        logs.push({
          path: absolute,
          text: await fs.readFile(absolute, "utf8"),
        });
      }
    }
  }
  let entries;
  try {
    entries = await fs.readdir(root, { withFileTypes: true });
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
  for (const entry of entries) {
    if (excludedRootEntries.has(entry.name)) continue;
    const absolute = path.join(root, entry.name);
    if (entry.isDirectory()) await visit(absolute);
    else if (entry.isFile() && entry.name.endsWith(".log")) {
      logs.push({
        path: absolute,
        text: await fs.readFile(absolute, "utf8"),
      });
    }
  }
  return logs;
}

async function verifyInMemorySecretStorage() {
  const receiptPath = process.env.SILMARIL_NATIVE_ISOLATION_RECEIPT_PATH;
  const userData = process.env.SILMARIL_NATIVE_USER_DATA;
  assert.ok(
    receiptPath && path.isAbsolute(receiptPath),
    "Missing secret-storage isolation receipt path",
  );
  assert.ok(userData && path.isAbsolute(userData));
  const existingLogDirectories = new Set(JSON.parse(
    process.env.SILMARIL_NATIVE_EXISTING_LOG_DIRECTORIES ?? "[]",
  ));
  const receipt = {
    schemaVersion: 1,
    isolation: "ephemeral-in-memory-secret-storage",
    flag: "--use-inmemory-secretstorage",
    result: "fail",
  };
  try {
    const deadline = Date.now() + 30_000;
    do {
      const logs = await readPrivateLogs(
        path.join(userData, "logs"),
        existingLogDirectories,
      );
      const mainLog = logs.find((entry) => entry.path.endsWith("/main.log"))?.text ?? "";
      const combinedLogs = logs.map((entry) => entry.text).join("\n");
      const selection = {
        launchFlagSelected:
          mainLog.includes('"use-inmemory-secretstorage":true'),
        inMemoryServiceSelected: combinedLogs.includes(
          "[SecretStorageService] Encryption is not available, falling back to in-memory storage",
        ),
        osEncryptionProbeObserved: combinedLogs.includes(
          "[EncryptionMainService] Checking if encryption is available",
        ),
        githubAuthenticationSecretApiReadObserved: combinedLogs.includes(
          "Reading sessions from keychain...",
        ),
      };
      if (selection.osEncryptionProbeObserved) {
        throw new Error(
          "OS encryption/keychain probing occurred despite required in-memory secret storage",
        );
      }
      if (selection.launchFlagSelected && selection.inMemoryServiceSelected) {
        receipt.selection = selection;
        receipt.checkedAt = new Date().toISOString();
        receipt.result = "pass";
        await writeCapture(receiptPath, receipt);
        return receipt;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    } while (Date.now() < deadline);
    throw new Error(
      "VS Code did not confirm forced in-memory secret storage within 30 seconds",
    );
  } catch (error) {
    receipt.error = {
      name: error instanceof Error ? error.name : "Error",
      message: error instanceof Error ? error.message : String(error),
    };
    await writeCapture(receiptPath, receipt);
    throw error;
  }
}

async function waitForNormalWorkspaceTrust() {
  if (vscode.workspace.isTrusted) return;
  const readyPath = process.env.SILMARIL_NATIVE_TRUST_READY_PATH;
  assert.ok(
    readyPath && path.isAbsolute(readyPath),
    "Missing normal-trust ready path",
  );
  const workspaceFile = vscode.workspace.workspaceFile?.fsPath;
  const workspace = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  assert.ok(workspaceFile && workspace, "Missing private QA workspace");
  await writeCapture(readyPath, {
    schemaVersion: 1,
    state: "normal-workspace-trust-required",
    readyAt: new Date().toISOString(),
    vscodeVersion: vscode.version,
    appName: vscode.env.appName,
    windowTitle: process.env.SILMARIL_NATIVE_WINDOW_TITLE,
    workspaceFile: await fs.realpath(workspaceFile),
    workspace: await fs.realpath(workspace),
    workspaceTrusted: false,
  });
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      listener.dispose();
      reject(new Error(
        "Timed out waiting for normal workspace trust in the VS Code UI",
      ));
    }, 180_000);
    const listener = vscode.workspace.onDidGrantWorkspaceTrust(() => {
      clearTimeout(timeout);
      listener.dispose();
      resolve();
    });
  });
}

async function waitForModels(vendor, id) {
  const deadline = Date.now() + 30_000;
  do {
    const models = await vscode.lm.selectChatModels({ vendor, id });
    if (models.length === 1) return models[0];
    await new Promise((resolve) => setTimeout(resolve, 100));
  } while (Date.now() < deadline);
  throw new Error(`Timed out waiting for unique dummy model ${vendor}/${id}`);
}

function titleGenerationCapture() {
  const configuration = vscode.workspace.getConfiguration(
    "chat.agentHost.experimental",
  );
  const inspected = configuration.inspect("titleGeneration");
  assert.ok(
    inspected,
    "Shared route requires the declared titleGeneration setting",
  );
  return {
    source: "vscode.workspace.getConfiguration().inspect()",
    key: "chat.agentHost.experimental.titleGeneration",
    effectiveValue: configuration.get("titleGeneration"),
    defaultValue: inspected.defaultValue,
    globalValue: inspected.globalValue,
    workspaceValue: inspected.workspaceValue,
    workspaceFolderValue: inspected.workspaceFolderValue,
  };
}

async function waitForSelectionActionAttestation(
  pendingPath,
  expectedModel,
  timeoutMs,
) {
  const deadline = Date.now() + timeoutMs;
  do {
    try {
      const value = JSON.parse(await fs.readFile(pendingPath, "utf8"));
      if (value.state === "normal-visible-shared-model-selected") {
        return validateSelectionActionAttestation(value, expectedModel);
      }
    } catch (error) {
      if (error?.code !== "ENOENT" && !(error instanceof SyntaxError)) {
        throw error;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  } while (Date.now() < deadline);
  throw new Error(
    "Timed out waiting for the coordinator's normal visible shared-session and wrapped-model selection attestation",
  );
}

async function prepareSharedModelHandoff(constants, publicModel) {
  const readyPath = process.env.SILMARIL_NATIVE_SHARED_MODEL_READY_PATH;
  const pendingPath = process.env.SILMARIL_NATIVE_SHARED_MODEL_PENDING_PATH;
  assert.ok(readyPath && path.isAbsolute(readyPath));
  assert.ok(pendingPath && path.isAbsolute(pendingPath));
  assert.notEqual(readyPath, pendingPath);
  await writeImmutableCapture(readyPath, {
    schemaVersion: 1,
    state: "normal-visible-shared-model-selection-required",
    readyAt: new Date().toISOString(),
    publicModel,
    sourceVerifiedBridge: {
      expectedTargetChatSessionType: "agent-host-copilotcli",
      expectedByokModelIdentifier:
        `${constants.VENDOR}/${constants.MODEL_ID}`,
      metadataSource: "signed-host-source-guard",
      stableApiExposesTheseFields: false,
    },
    normalUiActionsInOrder: {
      sessionHarness: {
        surface: "Chat session/harness picker",
        action: "select the advertised shared Copilot session/harness",
        expectedTargetSessionType: "agent-host-copilotcli",
        syntheticCommandPermitted: false,
        accountOrProviderSetupPermitted: false,
      },
      model: {
        surface: "Chat model picker",
        action: "select the host-published wrapped deterministic dummy",
        syntheticCommandPermitted: false,
        accountOrProviderSetupPermitted: false,
      },
    },
    stopUnverifiedIfEitherEntryIsAbsentOrRequiresAuthentication: true,
    modelSelectionDoesNotCreateTheSessionRoute: true,
    qualification: "pending-runtime-route-proof",
  });
  return await waitForSelectionActionAttestation(
    pendingPath,
    publicModel,
    300_000,
  );
}

async function runTurn(modelSelector, query, toolsInclude) {
  await vscode.commands.executeCommand("workbench.action.chat.newChat");
  return await vscode.commands.executeCommand("workbench.action.chat.open", {
    mode: "agent",
    query,
    modelSelector,
    toolsInclude,
    blockOnResponse: true,
  });
}

async function waitForFirstSharedTurnEvidence(timeoutMs = 5_000) {
  const userData = process.env.SILMARIL_NATIVE_USER_DATA;
  assert.ok(
    userData && path.isAbsolute(userData),
    "Missing fresh-profile user-data path for first-turn route proof",
  );
  const deadline = Date.now() + timeoutMs;
  do {
    const rows = await readFreshProfileTurnRows(userData);
    if (rows.length > 0) return validateFirstSharedTurnRows(rows);
    await new Promise((resolve) => setTimeout(resolve, 50));
  } while (Date.now() < deadline);
  return validateFirstSharedTurnRows([]);
}

async function run() {
  const capturePath = process.env.SILMARIL_NATIVE_CAPTURE_PATH;
  assert.ok(capturePath && path.isAbsolute(capturePath), "Missing private capture path");

  const devDeviceId = await readPrivateDeviceId();
  const receipt = {
    schemaVersion: 1,
    result: "fail",
    vscodeVersion: vscode.version,
    workspaceTrusted: vscode.workspace.isTrusted,
    devDeviceId,
    extension: {},
    turns: [],
  };
  let nativeState;

  try {
    for (const name of [
      "VSCODE_COPILOT_CHAT_TOKEN",
      "GITHUB_PAT",
      "GITHUB_OAUTH_TOKEN",
    ]) {
      assert.equal(process.env[name], undefined, `${name} must not enter native QA`);
    }
    assert.equal(
      devDeviceId,
      process.env.SILMARIL_NATIVE_SYNTHETIC_DEVICE_ID,
      "VS Code did not use the private synthetic device ID",
    );
    receipt.secretStorageIsolation = await verifyInMemorySecretStorage();
    const trustAction = workspaceTrustAction({
      workspaceTrusted: vscode.workspace.isTrusted,
      allowNormalTrustHandoff:
        process.env.SILMARIL_NATIVE_ALLOW_NORMAL_TRUST_HANDOFF === "1",
    });
    if (trustAction === "wait-for-normal-ui-trust") {
      await waitForNormalWorkspaceTrust();
    }
    receipt.workspaceTrusted = vscode.workspace.isTrusted;
    assert.equal(
      vscode.workspace.isTrusted,
      true,
      "Private QA workspace is not normally trusted; no trust bypass is permitted",
    );

    const inventoryPath = process.env.SILMARIL_NATIVE_EXTENSION_INVENTORY_PATH;
    assert.ok(
      inventoryPath && path.isAbsolute(inventoryPath),
      "Missing private extension inventory path",
    );
    const inventoryCapture = extensionInventoryCapture();
    await writeCapture(inventoryPath, inventoryCapture);
    receipt.extensionInventory = {
      path: inventoryPath,
      count: inventoryCapture.count,
      copilotChatMatches: inventoryCapture.copilotChatMatches,
    };

    let copilot = vscode.extensions.getExtension("github.copilot-chat");
    if (
      !copilot
      && process.env.SILMARIL_NATIVE_ALLOW_UI_ENABLE_HANDOFF === "1"
    ) {
      receipt.agentEnablement = {
        mode: "normal-ui",
        state: "waiting",
        beforeInventoryPath: inventoryPath,
      };
      const enabled = await waitForNormalUiAgentEnablement(inventoryCapture);
      copilot = enabled.extension;
      receipt.agentEnablement = {
        mode: "normal-ui",
        state: "registered",
        proof: enabled.proof,
        phases: enabled.phases,
      };
      const afterInventoryPath =
        process.env.SILMARIL_NATIVE_EXTENSION_INVENTORY_AFTER_ENABLE_PATH;
      assert.ok(
        afterInventoryPath && path.isAbsolute(afterInventoryPath),
        "Missing post-enablement extension inventory path",
      );
      const afterInventory = extensionInventoryCapture();
      await writeCapture(afterInventoryPath, afterInventory);
      receipt.agentEnablement.afterInventoryPath = afterInventoryPath;
      receipt.agentEnablement.afterInventoryCount = afterInventory.count;
      receipt.agentEnablement.afterInventoryCopilotChatMatches =
        afterInventory.copilotChatMatches;
    }
    assert.ok(
      copilot,
      "The signed app contains GitHub Copilot Chat, but it is absent from the public extension-host inventory",
    );
    receipt.extension.copilot = await verifyOrdinaryBuiltInCopilot(copilot);
    await copilot.activate();

    const qaExtension = vscode.extensions.getExtension(
      "silmaril-native-qa.silmaril-vscode-native-qa",
    );
    assert.ok(qaExtension, "Native QA extension was not registered");
    const api = await qaExtension.activate();
    receipt.extension.qa = {
      id: qaExtension.id,
      version: qaExtension.packageJSON.version,
    };
    const { constants, state, collectStrings } = api;
    nativeState = state;
    const selected = await waitForModels(constants.VENDOR, constants.MODEL_ID);
    const sessionRoute =
      process.env.SILMARIL_NATIVE_SESSION_ROUTE ?? "legacy-local";
    const expectedModelSelector =
      modelSelectorForRoute(constants, sessionRoute);
    let modelSelector = expectedModelSelector;
    receipt.model = {
      vendor: selected.vendor,
      id: selected.id,
      family: selected.family,
      version: selected.version,
    };
    receipt.sessionRoute = {
      configured: sessionRoute,
      modelSelector,
      status: sessionRoute === SHARED_COPILOT_ROUTE
        ? "pending-runtime-proof"
        : "legacy-local",
    };
    if (sessionRoute === SHARED_COPILOT_ROUTE) {
      const titleGeneration = titleGenerationCapture();
      assert.equal(titleGeneration.defaultValue, "utility");
      assert.equal(titleGeneration.globalValue, "activeAgent");
      assert.equal(titleGeneration.effectiveValue, "activeAgent");
      assert.equal(titleGeneration.workspaceValue, undefined);
      assert.equal(titleGeneration.workspaceFolderValue, undefined);
      receipt.sessionRoute.titleGeneration = titleGeneration;
      const wrapped = [await waitForModels(
        expectedModelSelector.vendor,
        expectedModelSelector.id,
      )];
      const publicModel = validateWrappedModels(wrapped, constants);
      receipt.sessionRoute.publicWrappedModel = publicModel;
      receipt.sessionRoute.selectionAttestation =
        await prepareSharedModelHandoff(constants, publicModel);
      modelSelector = modelSelectorFromPublicModel(publicModel);
      receipt.sessionRoute.modelSelector = modelSelector;
    }

    const turnInputs = [
      {
        name: "allow-transformed",
        query: ALLOW_QUERY,
        tools: [constants.POST_TOOL],
      },
      {
        name: "block-transformed",
        query: BLOCK_QUERY,
        tools: [constants.POST_TOOL],
      },
      {
        name: "pre-tool-block",
        query: PRE_QUERY,
        tools: [constants.PRE_TOOL],
      },
      {
        name: "post-tool-replacement",
        query: POST_QUERY,
        tools: [constants.POST_TOOL],
      },
    ];
    for (const [index, input] of turnInputs.entries()) {
      const requestStart = state.providerRequests.length;
      const result = await runTurn(modelSelector, input.query, input.tools);
      receipt.turns.push({
        name: input.name,
        query: input.query,
        commandResult: result,
        providerRequestStart: requestStart,
        providerRequestEnd: state.providerRequests.length,
      });
      if (sessionRoute === SHARED_COPILOT_ROUTE && index === 0) {
        receipt.sessionRoute.firstTurnEvidence =
          await waitForFirstSharedTurnEvidence();
      }
    }

    const preMarkerPath = process.env.SILMARIL_NATIVE_PRE_MARKER_PATH;
    assert.ok(preMarkerPath && path.isAbsolute(preMarkerPath));
    await assert.rejects(
      fs.access(preMarkerPath),
      (error) => error?.code === "ENOENT",
      "Blocked pre-tool side effect marker exists",
    );
    assert.equal(state.toolInvocations[constants.PRE_TOOL], 0);
    assert.equal(state.toolInvocations[constants.POST_TOOL], 1);

    const providerStrings = collectStrings(state.providerRequests);
    assert.equal(
      providerStrings.some((value) => value.includes(BLOCK_QUERY)),
      false,
      "Blocked prompt reached the dummy provider",
    );
    assert.equal(
      providerStrings.some((value) => value.includes(constants.POISON_MARKER)),
      false,
      "Post-tool poison reached the next dummy-provider request",
    );

    receipt.providerRequests = state.providerRequests;
    receipt.toolInvocations = state.toolInvocations;
    receipt.preToolMarkerAbsent = true;
    receipt.result = "pass";
  } catch (error) {
    receipt.error = {
      name: error instanceof Error ? error.name : "Error",
      message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    };
    throw error;
  } finally {
    snapshotNativeState(receipt, nativeState);
    await writeCapture(capturePath, receipt);
  }
}

module.exports = { run };
