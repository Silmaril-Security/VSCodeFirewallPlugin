"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");

const SHARED_COPILOT_ROUTE = "shared-copilot";
const WRAPPED_VENDOR = "agent-host-copilotcli";

function wrappedModelId(constants) {
  return `${constants.VENDOR}/${constants.MODEL_ID}`;
}

function modelSelectorForRoute(constants, sessionRoute) {
  if (sessionRoute === "legacy-local") {
    return {
      vendor: constants.VENDOR,
      id: constants.MODEL_ID,
    };
  }
  assert.equal(
    sessionRoute,
    SHARED_COPILOT_ROUTE,
    `Unsupported native session route: ${sessionRoute}`,
  );
  return {
    vendor: WRAPPED_VENDOR,
    id: wrappedModelId(constants),
  };
}

function publicModelReceipt(model) {
  return {
    source: "vscode.lm.selectChatModels",
    name: model.name,
    vendor: model.vendor,
    id: model.id,
    family: model.family,
    version: model.version,
    maxInputTokens: model.maxInputTokens,
  };
}

function modelSelectorFromPublicModel(publicModel) {
  assert.ok(publicModel && typeof publicModel === "object");
  assert.equal(typeof publicModel.vendor, "string");
  assert.ok(publicModel.vendor.length > 0);
  assert.equal(typeof publicModel.id, "string");
  assert.ok(publicModel.id.length > 0);
  return {
    vendor: publicModel.vendor,
    id: publicModel.id,
  };
}

function validateWrappedModels(models, constants) {
  assert.ok(Array.isArray(models));
  assert.equal(
    models.length,
    1,
    "Expected exactly one host-published wrapped dummy model",
  );
  const [model] = models;
  assert.equal(model.vendor, WRAPPED_VENDOR);
  assert.equal(model.id, wrappedModelId(constants));
  assert.notEqual(
    model.vendor,
    constants.VENDOR,
    "Unwrapped Local dummy cannot satisfy the shared model gate",
  );
  assert.ok(typeof model.name === "string" && model.name.length > 0);
  assert.ok(typeof model.family === "string" && model.family.length > 0);
  assert.ok(typeof model.version === "string" && model.version.length > 0);
  return publicModelReceipt(model);
}

function validateSelectionActionAttestation(value, expectedModel) {
  assert.equal(value?.schemaVersion, 1);
  assert.equal(value?.state, "normal-visible-shared-model-selected");
  assert.equal(value?.kind, "human-ui-selection-action-only");
  assert.equal(
    value?.normalUiActions?.sessionHarness?.surface,
    "Chat session/harness picker",
  );
  assert.equal(
    value?.normalUiActions?.sessionHarness?.syntheticCommandUsed,
    false,
  );
  assert.equal(
    value?.normalUiActions?.sessionHarness?.observedTargetSessionType,
    WRAPPED_VENDOR,
  );
  assert.ok(
    [
      "normal-visible-ui",
      "fresh-profile-host-log",
    ].includes(
      value?.normalUiActions?.sessionHarness?.observationSource,
    ),
    "Shared session/harness target must be observed in normal visible UI or the fresh-profile host log",
  );
  assert.equal(
    value?.normalUiActions?.model?.surface,
    "Chat model picker",
  );
  assert.equal(
    value?.normalUiActions?.model?.syntheticCommandUsed,
    false,
  );
  assert.deepEqual(value?.selectedPublicModel, {
    vendor: expectedModel.vendor,
    id: expectedModel.id,
  });
  assert.equal(
    value?.executionProof,
    false,
    "A visible-selection attestation must never claim execution proof",
  );
  return {
    kind: "human-ui-selection-action-only",
    executionProof: false,
    normalUiActions: structuredClone(value.normalUiActions),
    selectedPublicModel: {
      vendor: expectedModel.vendor,
      id: expectedModel.id,
    },
  };
}

function parseChatTurnRows(logs) {
  const rows = [];
  let sequence = 0;
  for (const log of logs) {
    const lines = log.text.split(/\r?\n/u);
    for (let index = 0; index < lines.length; index += 1) {
      const marker = "[ChatTTFP] end ";
      const markerOffset = lines[index].indexOf(marker);
      if (markerOffset < 0) continue;
      try {
        const row = JSON.parse(
          lines[index].slice(markerOffset + marker.length),
        );
        if (row.interactionKind !== "turn") continue;
        rows.push({
          ...row,
          logFile: log.relativePath,
          logLine: index + 1,
          _sequence: sequence,
        });
        sequence += 1;
      } catch {
        // Malformed rows are not positive route evidence.
      }
    }
  }
  return rows.sort((left, right) => {
    const leftEpoch = Number.isFinite(left.epochMs)
      ? left.epochMs
      : Number.POSITIVE_INFINITY;
    const rightEpoch = Number.isFinite(right.epochMs)
      ? right.epochMs
      : Number.POSITIVE_INFINITY;
    return leftEpoch - rightEpoch || left._sequence - right._sequence;
  });
}

function validateFirstSharedTurnRows(rows) {
  assert.ok(Array.isArray(rows));
  assert.ok(rows.length > 0, "Missing first-turn ChatTTFP runtime metadata");
  assert.equal(
    rows[0].sessionType,
    WRAPPED_VENDOR,
    "First safe allow turn did not execute in agent-host-copilotcli",
  );
  assert.equal(
    rows.every((row) => row.sessionType === WRAPPED_VENDOR),
    true,
    "Local or mixed ChatTTFP turn metadata observed after first safe allow turn",
  );
  return {
    source: "fresh-profile-renderer-logs",
    observedTurnCount: rows.length,
    firstTurn: {
      chatSessionId: rows[0].chatSessionId,
      sessionType: rows[0].sessionType,
      agent: rows[0].agent,
      model: rows[0].model,
      epochMs: rows[0].epochMs,
      logFile: rows[0].logFile,
      logLine: rows[0].logLine,
    },
  };
}

async function readFreshProfileTurnRows(userData) {
  assert.ok(
    userData && path.isAbsolute(userData),
    "Fresh-profile user-data path must be absolute",
  );
  const resolvedUserData = await fs.realpath(userData);
  assert.equal(
    resolvedUserData,
    path.resolve(userData),
    "Fresh-profile user-data path must not resolve through a symlink",
  );
  const logsRoot = path.join(resolvedUserData, "logs");
  const resolvedLogsRoot = await fs.realpath(logsRoot).catch((error) => {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  });
  if (!resolvedLogsRoot) return [];
  assert.equal(
    path.relative(resolvedUserData, resolvedLogsRoot).startsWith(".."),
    false,
    "Fresh-profile logs path escaped user data",
  );
  const logs = [];
  const visit = async (directory) => {
    const directoryInfo = await fs.lstat(directory);
    assert.equal(directoryInfo.isSymbolicLink(), false);
    assert.equal(directoryInfo.isDirectory(), true);
    const entries = await fs.readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(absolute);
      } else if (entry.isFile() && entry.name === "renderer.log") {
        const info = await fs.lstat(absolute);
        if (!info.isFile() || info.isSymbolicLink()) continue;
        logs.push({
          relativePath: path.relative(logsRoot, absolute),
          text: await fs.readFile(absolute, "utf8"),
        });
      }
    }
  };
  await visit(resolvedLogsRoot);
  return parseChatTurnRows(logs);
}

module.exports = {
  SHARED_COPILOT_ROUTE,
  WRAPPED_VENDOR,
  modelSelectorForRoute,
  modelSelectorFromPublicModel,
  parseChatTurnRows,
  publicModelReceipt,
  readFreshProfileTurnRows,
  validateSelectionActionAttestation,
  validateFirstSharedTurnRows,
  validateWrappedModels,
  wrappedModelId,
};
