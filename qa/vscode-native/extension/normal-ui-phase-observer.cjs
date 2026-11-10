"use strict";

const { createHash } = require("node:crypto");
const {
  classifyExactSettingDelta,
} = require("./agent-ui-policy.cjs");

const MAX_POLL_INTERVAL_MS = 250;

function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function configurationMatchesPhase(phase, configuration) {
  if (phase === "disable-profile") {
    return configuration.effectiveValue === true
      && configuration.globalValue === true
      && configuration.workspaceValue === null
      && configuration.workspaceFolderValue === null;
  }
  if (phase === "enable-workspace") {
    return configuration.effectiveValue === false
      && configuration.globalValue === true
      && configuration.workspaceValue === false
      && configuration.workspaceFolderValue === null;
  }
  throw new Error(`Unsupported normal-UI phase: ${phase}`);
}

function classifyNormalUiPhase({
  phase,
  beforeProfileSettingsBytes,
  beforeWorkspaceBytes,
  observedProfileSettingsBytes,
  observedWorkspaceBytes,
  configuration,
  extensionIdentityState = "not-required",
}) {
  const profileDelta = classifyExactSettingDelta({
    baselineBytes: beforeProfileSettingsBytes,
    observedBytes: observedProfileSettingsBytes,
    value: true,
    description: "private profile settings",
  });
  const workspaceDelta = classifyExactSettingDelta({
    baselineBytes: beforeWorkspaceBytes,
    observedBytes: observedWorkspaceBytes,
    container: "settings",
    value: false,
    description: "owned workspace file",
  });
  const configurationMatches = configurationMatchesPhase(
    phase,
    configuration,
  );
  const exactFileDeltaMatches = phase === "disable-profile"
    ? profileDelta.state === "expected-ui-delta"
      && workspaceDelta.state === "unchanged"
    : profileDelta.state === "expected-ui-delta"
      && workspaceDelta.state === "expected-ui-delta";
  const extensionIdentityMatches = phase === "disable-profile"
    || extensionIdentityState === "verified";
  const terminalIdentityConflict =
    extensionIdentityState === "conflict";

  let evidenceClassification = "pending";
  if (
    profileDelta.state === "unchanged"
    && workspaceDelta.state === "unchanged"
    && !configurationMatches
  ) {
    evidenceClassification = "no-approved-action-observed";
  } else if (configurationMatches && !exactFileDeltaMatches) {
    evidenceClassification =
      "public-configuration-matched-exact-file-delta-missing";
  } else if (exactFileDeltaMatches && !configurationMatches) {
    evidenceClassification =
      "exact-file-delta-observed-public-scope-conflict";
  } else if (terminalIdentityConflict) {
    evidenceClassification = "signed-extension-identity-conflict";
  } else if (
    phase === "enable-workspace"
    && extensionIdentityState !== "verified"
  ) {
    evidenceClassification = "signed-extension-not-registered";
  } else if (
    configurationMatches
    && exactFileDeltaMatches
    && extensionIdentityMatches
  ) {
    evidenceClassification = "approved-phase-observed";
  }

  return {
    success:
      configurationMatches
      && exactFileDeltaMatches
      && extensionIdentityMatches,
    terminalIdentityConflict,
    evidenceClassification,
    configurationMatches,
    exactFileDeltaMatches,
    extensionIdentityMatches,
    configuration: {
      source: configuration.source,
      key: configuration.key,
      effectiveValue: configuration.effectiveValue,
      defaultValue: configuration.defaultValue,
      globalValue: configuration.globalValue,
      workspaceValue: configuration.workspaceValue,
      workspaceFolderValue: configuration.workspaceFolderValue,
    },
    profileDelta,
    workspaceDelta,
  };
}

function phaseDiagnostic({
  phase,
  paths,
  observer,
  proof,
  failure,
  beforeProfileSettingsBytes,
  beforeWorkspaceBytes,
  observedProfileSettingsBytes,
  observedWorkspaceBytes,
  observedConfiguration,
}) {
  const supportedInterpretation = (() => {
    if (proof?.evidenceClassification === "no-approved-action-observed") {
      return "no-approved-action-observed";
    }
    if (
      proof?.evidenceClassification
      === "public-configuration-matched-exact-file-delta-missing"
    ) {
      return "wrong-profile-or-profile-source-mismatch-possible-not-proven";
    }
    if (
      proof?.evidenceClassification
      === "exact-file-delta-observed-public-scope-conflict"
    ) {
      return "wrong-scope-or-public-configuration-conflict";
    }
    if (
      proof?.success
      && observer.eventCounts.configuration === 0
      && observer.eventCounts.extensions === 0
    ) {
      return "ordinary-event-not-observed-periodic-read-completed";
    }
    return "no-more-specific-cause-proven";
  })();
  const observedHash = (value) =>
    value instanceof Uint8Array ? sha256Bytes(value) : undefined;
  const profileObservedSha256 = observedHash(observedProfileSettingsBytes);
  const workspaceObservedSha256 = observedHash(observedWorkspaceBytes);
  const profileSettings = {
    beforeSha256: sha256Bytes(beforeProfileSettingsBytes),
    ...(profileObservedSha256 === undefined
      ? {}
      : { observedSha256: profileObservedSha256 }),
    ...(proof?.profileDelta ? { delta: proof.profileDelta } : {}),
  };
  const workspace = {
    beforeSha256: sha256Bytes(beforeWorkspaceBytes),
    ...(workspaceObservedSha256 === undefined
      ? {}
      : { observedSha256: workspaceObservedSha256 }),
    ...(proof?.workspaceDelta ? { delta: proof.workspaceDelta } : {}),
  };
  const safeConfiguration = (() => {
    if (!observedConfiguration || typeof observedConfiguration !== "object") {
      return undefined;
    }
    const result = {};
    for (const key of [
      "source",
      "key",
      "effectiveValue",
      "defaultValue",
      "globalValue",
      "workspaceValue",
      "workspaceFolderValue",
    ]) {
      const value = observedConfiguration[key];
      if (
        typeof value === "boolean"
        || value === null
        || (key === "key" && value === "chat.disableAIFeatures")
        || (
          key === "source"
          && value === "vscode.workspace.getConfiguration().inspect()"
        )
      ) {
        result[key] = value;
      }
    }
    return result;
  })();
  return {
    phase,
    ...(proof?.evidenceClassification
      ? { evidenceClassification: proof.evidenceClassification }
      : {}),
    supportedInterpretation,
    ...(failure ? { failure } : {}),
    observer,
    ...(proof?.configuration
      ? { configuration: proof.configuration }
      : safeConfiguration
        ? { configuration: safeConfiguration }
        : {}),
    paths: {
      profileResolvedPath: paths.profileResolvedPath,
      profileSettingsPath: paths.profileSettingsPath,
      userDataPath: paths.userDataPath,
      workspaceFilePath: paths.workspaceFilePath,
    },
    files: {
      profileSettings,
      workspace,
    },
  };
}

function observerError(message, diagnostic) {
  const error = new Error(message);
  error.normalUiPhaseDiagnostic = diagnostic;
  return error;
}

async function readObservationBeforeDeadline(readObservation, deadlineMs) {
  const remainingMs = deadlineMs - Date.now();
  if (remainingMs <= 0) return { kind: "timeout" };
  let timer;
  const readOutcome = Promise.resolve()
    .then(readObservation)
    .then(
      (observation) => ({ kind: "value", observation }),
      () => ({ kind: "rejected" }),
    );
  const timeoutOutcome = new Promise((resolve) => {
    timer = setTimeout(
      () => resolve({ kind: "timeout" }),
      remainingMs,
    );
  });
  const outcome = await Promise.race([readOutcome, timeoutOutcome]);
  clearTimeout(timer);
  if (outcome.kind === "value" && Date.now() >= deadlineMs) {
    return { kind: "timeout" };
  }
  return outcome;
}

function immutableExtensionIdentity(proof) {
  const identity = proof?.identity;
  if (
    !identity
    || typeof identity.id !== "string"
    || typeof identity.version !== "string"
    || identity.isBuiltin !== true
    || typeof identity.canonicalPath !== "string"
    || typeof identity.manifestSha256 !== "string"
    || typeof identity.sourceSha256 !== "string"
  ) {
    throw new Error("Verified extension proof lacks immutable identity");
  }
  return {
    id: identity.id,
    version: identity.version,
    isBuiltin: identity.isBuiltin,
    canonicalPath: identity.canonicalPath,
    manifestSha256: identity.manifestSha256,
    sourceSha256: identity.sourceSha256,
  };
}

function sameImmutableExtensionIdentity(left, right) {
  return left.id === right.id
    && left.version === right.version
    && left.isBuiltin === right.isBuiltin
    && left.canonicalPath === right.canonicalPath
    && left.manifestSha256 === right.manifestSha256
    && left.sourceSha256 === right.sourceSha256;
}

function createLiveExtensionIdentityTracker({
  getCurrentExtension,
  verifyExtension,
}) {
  let stableExtensionReference;
  let acceptedProof;
  let acceptedIdentity;

  const clear = () => {
    stableExtensionReference = undefined;
    acceptedProof = undefined;
    acceptedIdentity = undefined;
  };

  return {
    async observe() {
      const current = getCurrentExtension();
      if (!current) {
        clear();
        return { state: "absent" };
      }
      if (current === stableExtensionReference && acceptedProof) {
        return {
          state: "verified",
          extension: stableExtensionReference,
          proof: acceptedProof,
          proofSource: "stable-reference-cache",
        };
      }
      try {
        const proof = await verifyExtension(current);
        const identity = immutableExtensionIdentity(proof);
        if (
          acceptedIdentity
          && !sameImmutableExtensionIdentity(acceptedIdentity, identity)
        ) {
          clear();
          return { state: "conflict" };
        }
        stableExtensionReference = current;
        acceptedProof = proof;
        acceptedIdentity = identity;
        return {
          state: "verified",
          extension: stableExtensionReference,
          proof: acceptedProof,
          proofSource: "fresh-verification",
        };
      } catch {
        clear();
        return { state: "conflict" };
      }
    },

    async verifyCurrentAccepted() {
      const before = getCurrentExtension();
      if (!before) {
        clear();
        throw new Error(
          "Signed built-in extension was absent at final phase-two verification",
        );
      }
      if (!acceptedIdentity || !acceptedProof) {
        clear();
        throw new Error(
          "Phase two has no accepted signed extension identity",
        );
      }
      const beforeProof = await verifyExtension(before);
      const beforeIdentity = immutableExtensionIdentity(beforeProof);
      if (
        !sameImmutableExtensionIdentity(acceptedIdentity, beforeIdentity)
      ) {
        clear();
        throw new Error(
          "Currently registered extension identity differs from the phase-two accepted identity",
        );
      }
      const after = getCurrentExtension();
      if (!after) {
        clear();
        throw new Error(
          "Signed built-in extension was removed during final phase-two verification",
        );
      }
      const afterProof = await verifyExtension(after);
      const afterIdentity = immutableExtensionIdentity(afterProof);
      if (
        !sameImmutableExtensionIdentity(acceptedIdentity, afterIdentity)
        || !sameImmutableExtensionIdentity(beforeIdentity, afterIdentity)
      ) {
        clear();
        throw new Error(
          "Registered extension immutable identity changed during final phase-two verification",
        );
      }
      stableExtensionReference = after;
      acceptedProof = afterProof;
      return {
        extension: after,
        proof: afterProof,
        proofSource: "fresh-final-verification",
      };
    },
  };
}

async function observeNormalUiPhase({
  phase,
  paths,
  beforeProfileSettingsBytes,
  beforeWorkspaceBytes,
  readObservation,
  stages,
  pollIntervalMs = 100,
  timeOrigin,
  subscribeConfiguration,
  subscribeExtensions,
}) {
  if (
    !Number.isFinite(pollIntervalMs)
    || pollIntervalMs <= 0
    || pollIntervalMs > MAX_POLL_INTERVAL_MS
  ) {
    throw new Error(
      `Normal-UI polling interval must be between 1 and ${MAX_POLL_INTERVAL_MS}ms`,
    );
  }
  if (!Array.isArray(stages) || stages.length === 0) {
    throw new Error("Normal-UI phase observer requires bounded stages");
  }
  for (const stage of stages) {
    if (
      typeof stage.label !== "string"
      || !Number.isFinite(stage.timeoutMs)
      || stage.timeoutMs <= 0
      || typeof stage.isSatisfied !== "function"
    ) {
      throw new Error("Invalid normal-UI observer stage");
    }
  }

  const startedAtMs = Date.now();
  const observer = {
    timeOrigin,
    startedAt: new Date(startedAtMs).toISOString(),
    pollIntervalMs,
    eventCounts: {
      configuration: 0,
      extensions: 0,
    },
    pollCount: 0,
    stages: [],
    completionSource: "not-complete",
  };
  let wake;
  const signalWake = () => {
    const resolve = wake;
    wake = undefined;
    resolve?.();
  };
  const disposables = [];
  if (subscribeConfiguration) {
    disposables.push(subscribeConfiguration(() => {
      observer.eventCounts.configuration += 1;
      signalWake();
    }));
  }
  if (subscribeExtensions) {
    disposables.push(subscribeExtensions(() => {
      observer.eventCounts.extensions += 1;
      signalWake();
    }));
  }

  let observation;
  let proof;
  let lastObservation;
  let lastProof;
  try {
    for (const stage of stages) {
      const stageStartedAtMs = Date.now();
      const deadlineMs = stageStartedAtMs + stage.timeoutMs;
      const stageReceipt = {
        label: stage.label,
        timeoutMs: stage.timeoutMs,
        timeOrigin: stage.timeOrigin,
        startedAt: new Date(stageStartedAtMs).toISOString(),
        deadlineAt: new Date(deadlineMs).toISOString(),
      };
      observer.stages.push(stageReceipt);
      while (true) {
        observer.pollCount += 1;
        observation = undefined;
        proof = undefined;
        const failStage = (
          code,
          category,
          message,
          useLastEvidence = false,
        ) => {
          const diagnosticObservation = observation
            ?? (useLastEvidence ? lastObservation : undefined);
          const diagnosticProof = proof
            ?? (useLastEvidence ? lastProof : undefined);
          stageReceipt.failedAt = new Date().toISOString();
          const diagnostic = phaseDiagnostic({
            phase,
            paths,
            observer,
            proof: diagnosticProof,
            failure: {
              code,
              category,
              stage: stage.label,
            },
            beforeProfileSettingsBytes,
            beforeWorkspaceBytes,
            observedProfileSettingsBytes:
              diagnosticObservation?.observedProfileSettingsBytes,
            observedWorkspaceBytes:
              diagnosticObservation?.observedWorkspaceBytes,
            observedConfiguration:
              diagnosticObservation?.configuration,
          });
          throw observerError(message, diagnostic);
        };
        const readOutcome = await readObservationBeforeDeadline(
          readObservation,
          deadlineMs,
        );
        if (readOutcome.kind === "timeout") {
          failStage(
            "NORMAL_UI_OBSERVATION_READ_TIMEOUT",
            "observation-read-timeout",
            `Normal-UI ${phase} observation read exceeded the bounded stage deadline`,
            true,
          );
        }
        if (readOutcome.kind === "rejected") {
          failStage(
            "NORMAL_UI_OBSERVATION_READ_FAILED",
            "observation-read-failure",
            `Normal-UI ${phase} observation read failed`,
            true,
          );
        }
        observation = readOutcome.observation;
        try {
          proof = classifyNormalUiPhase({
            phase,
            beforeProfileSettingsBytes,
            beforeWorkspaceBytes,
            observedProfileSettingsBytes:
              observation.observedProfileSettingsBytes,
            observedWorkspaceBytes: observation.observedWorkspaceBytes,
            configuration: observation.configuration,
            extensionIdentityState: observation.extensionIdentityState,
          });
        } catch {
          failStage(
            "NORMAL_UI_OBSERVATION_CLASSIFICATION_FAILED",
            "observation-classification-failure",
            `Normal-UI ${phase} observation classification failed`,
          );
        }
        lastObservation = observation;
        lastProof = proof;
        if (proof.terminalIdentityConflict) {
          failStage(
            "NORMAL_UI_EXTENSION_IDENTITY_CONFLICT",
            "extension-identity-conflict",
            `Normal-UI ${phase} observed a conflicting signed extension identity`,
          );
        }
        let satisfied;
        try {
          satisfied = stage.isSatisfied(proof);
        } catch {
          failStage(
            "NORMAL_UI_STAGE_EVALUATION_FAILED",
            "stage-evaluation-failure",
            `Normal-UI ${phase} stage evaluation failed`,
          );
        }
        if (satisfied) {
          if (Date.now() >= deadlineMs) {
            failStage(
              "NORMAL_UI_STAGE_TIMEOUT",
              "stage-timeout",
              `Normal-UI ${phase} stage deadline elapsed before proof acceptance`,
            );
          }
          stageReceipt.completedAt = new Date().toISOString();
          break;
        }
        const remainingMs = deadlineMs - Date.now();
        if (remainingMs <= 0) {
          failStage(
            "NORMAL_UI_STAGE_TIMEOUT",
            "stage-timeout",
            `Timed out in normal-UI ${phase} stage ${stage.label}`,
          );
        }
        await new Promise((resolve) => {
          let timer;
          const wakeHandler = () => {
            clearTimeout(timer);
            if (wake === wakeHandler) wake = undefined;
            resolve();
          };
          timer = setTimeout(() => {
            if (wake === wakeHandler) wake = undefined;
            resolve();
          }, Math.min(pollIntervalMs, remainingMs));
          wake = wakeHandler;
        });
      }
    }

    if (!proof?.success) {
      const diagnostic = phaseDiagnostic({
        phase,
        paths,
        observer,
        proof,
        failure: {
          code: "NORMAL_UI_PHASE_INCOMPLETE",
          category: "phase-proof-incomplete",
        },
        beforeProfileSettingsBytes,
        beforeWorkspaceBytes,
        observedProfileSettingsBytes:
          observation.observedProfileSettingsBytes,
        observedWorkspaceBytes: observation.observedWorkspaceBytes,
      });
      throw observerError(
        `Normal-UI ${phase} stages completed without complete approved proof`,
        diagnostic,
      );
    }
    observer.completionSource =
      observer.eventCounts.configuration === 0
      && observer.eventCounts.extensions === 0
        ? "periodic-read-without-observed-event"
        : "ordinary-event-or-periodic-read";
    return {
      proof,
      diagnostic: phaseDiagnostic({
        phase,
        paths,
        observer,
        proof,
        beforeProfileSettingsBytes,
        beforeWorkspaceBytes,
        observedProfileSettingsBytes:
          observation.observedProfileSettingsBytes,
        observedWorkspaceBytes: observation.observedWorkspaceBytes,
      }),
    };
  } finally {
    signalWake();
    for (const disposable of disposables) {
      disposable?.dispose();
    }
  }
}

module.exports = {
  MAX_POLL_INTERVAL_MS,
  classifyNormalUiPhase,
  configurationMatchesPhase,
  createLiveExtensionIdentityTracker,
  observeNormalUiPhase,
};
