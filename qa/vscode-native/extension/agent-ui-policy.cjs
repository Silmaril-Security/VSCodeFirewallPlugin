"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");

const AI_SETTING = "chat.disableAIFeatures";

function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function parseObject(bytes, description) {
  const value = JSON.parse(Buffer.from(bytes).toString("utf8"));
  assert.ok(
    value && typeof value === "object" && !Array.isArray(value),
    `${description} must be a JSON object`,
  );
  return value;
}

function expectedSettingValue(bytes, container, value, description) {
  const expected = structuredClone(parseObject(bytes, description));
  const target = container === undefined
    ? expected
    : expected[container];
  assert.ok(
    target && typeof target === "object" && !Array.isArray(target),
    `${description} ${container ?? "root"} must be a JSON object`,
  );
  target[AI_SETTING] = value;
  return expected;
}

function classifyExactSettingDelta({
  baselineBytes,
  observedBytes,
  container,
  value,
  description,
}) {
  const baseline = Buffer.from(baselineBytes);
  const observed = Buffer.from(observedBytes);
  if (baseline.equals(observed)) {
    return {
      state: "unchanged",
      expected: true,
      beforeSha256: sha256Bytes(baseline),
      observedSha256: sha256Bytes(observed),
    };
  }
  const expected = expectedSettingValue(
    baseline,
    container,
    value,
    description,
  );
  const actual = parseObject(observed, description);
  const matches = (() => {
    try {
      assert.deepEqual(actual, expected);
      return true;
    } catch {
      return false;
    }
  })();
  return {
    state: matches ? "expected-ui-delta" : "unexpected",
    expected: matches,
    beforeSha256: sha256Bytes(baseline),
    observedSha256: sha256Bytes(observed),
    setting: AI_SETTING,
    scope: container === undefined ? "profile" : container,
    value,
  };
}

function classifyFreshProfileUiFiles({
  activeSettingsBytes,
  activeConfigBytes,
  originalWorkspaceBytes,
  observedSettingsBytes,
  observedConfigBytes,
  observedWorkspaceBytes,
}) {
  const settings = classifyExactSettingDelta({
    baselineBytes: activeSettingsBytes,
    observedBytes: observedSettingsBytes,
    value: true,
    description: "private profile settings",
  });
  const workspace = classifyExactSettingDelta({
    baselineBytes: originalWorkspaceBytes,
    observedBytes: observedWorkspaceBytes,
    container: "settings",
    value: false,
    description: "owned workspace file",
  });
  const config = {
    state: Buffer.from(activeConfigBytes).equals(Buffer.from(observedConfigBytes))
      ? "unchanged"
      : "unexpected",
    expected: Buffer.from(activeConfigBytes).equals(Buffer.from(observedConfigBytes)),
    beforeSha256: sha256Bytes(Buffer.from(activeConfigBytes)),
    observedSha256: sha256Bytes(Buffer.from(observedConfigBytes)),
  };
  const phaseOrderValid = !(
    workspace.state === "expected-ui-delta"
    && settings.state !== "expected-ui-delta"
  );
  return {
    expected: settings.expected
      && workspace.expected
      && config.expected
      && phaseOrderValid,
    expectedUiTransitionObserved:
      settings.state === "expected-ui-delta"
      && workspace.state === "expected-ui-delta",
    phaseOrderValid,
    settings,
    config,
    workspace,
  };
}

module.exports = {
  AI_SETTING,
  classifyExactSettingDelta,
  classifyFreshProfileUiFiles,
  sha256Bytes,
};
