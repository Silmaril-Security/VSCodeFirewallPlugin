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
  beforeProfileSettingsBytes,
  beforeWorkspaceBytes,
  observedProfileSettingsBytes,
  observedWorkspaceBytes,
}) {
  const supportedInterpretation = (() => {
    if (proof.evidenceClassification === "no-approved-action-observed") {
      return "no-approved-action-observed";
    }
    if (
      proof.evidenceClassification
      === "public-configuration-matched-exact-file-delta-missing"
    ) {
      return "wrong-profile-or-profile-source-mismatch-possible-not-proven";
    }
    if (
      proof.evidenceClassification
      === "exact-file-delta-observed-public-scope-conflict"
    ) {
      return "wrong-scope-or-public-configuration-conflict";
    }
    if (
      proof.success
      && observer.eventCounts.configuration === 0
      && observer.eventCounts.extensions === 0
    ) {
      return "ordinary-event-not-observed-periodic-read-completed";
    }
    return "no-more-specific-cause-proven";
  })();
  return {
    phase,
    evidenceClassification: proof.evidenceClassification,
    supportedInterpretation,
    observer,
    configuration: proof.configuration,
    paths: {
      profileResolvedPath: paths.profileResolvedPath,
      profileSettingsPath: paths.profileSettingsPath,
      userDataPath: paths.userDataPath,
      workspaceFilePath: paths.workspaceFilePath,
    },
    files: {
      profileSettings: {
        beforeSha256: sha256Bytes(beforeProfileSettingsBytes),
        observedSha256: sha256Bytes(observedProfileSettingsBytes),
        delta: proof.profileDelta,
      },
      workspace: {
        beforeSha256: sha256Bytes(beforeWorkspaceBytes),
        observedSha256: sha256Bytes(observedWorkspaceBytes),
        delta: proof.workspaceDelta,
      },
    },
  };
}

function observerError(message, diagnostic) {
  const error = new Error(message);
  error.normalUiPhaseDiagnostic = diagnostic;
  return error;
}

function createLiveExtensionIdentityTracker({
  getCurrentExtension,
  verifyExtension,
}) {
  let acceptedExtension;
  let acceptedProof;

  const clear = () => {
    acceptedExtension = undefined;
    acceptedProof = undefined;
  };

  return {
    async observe() {
      const current = getCurrentExtension();
      if (!current) {
        clear();
        return { state: "absent" };
      }
      if (current === acceptedExtension && acceptedProof) {
        return {
          state: "verified",
          extension: acceptedExtension,
          proof: acceptedProof,
          proofSource: "stable-reference-cache",
        };
      }
      try {
        const proof = await verifyExtension(current);
        acceptedExtension = current;
        acceptedProof = proof;
        return {
          state: "verified",
          extension: acceptedExtension,
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
      if (before !== acceptedExtension || !acceptedProof) {
        clear();
        throw new Error(
          "Currently registered extension does not match the phase-two accepted extension",
        );
      }
      const proof = await verifyExtension(before);
      const after = getCurrentExtension();
      if (after !== before) {
        clear();
        throw new Error(
          "Registered extension changed during final phase-two verification",
        );
      }
      acceptedProof = proof;
      return {
        extension: before,
        proof,
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
        observation = await readObservation();
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
        if (proof.terminalIdentityConflict) {
          const diagnostic = phaseDiagnostic({
            phase,
            paths,
            observer,
            proof,
            beforeProfileSettingsBytes,
            beforeWorkspaceBytes,
            observedProfileSettingsBytes:
              observation.observedProfileSettingsBytes,
            observedWorkspaceBytes: observation.observedWorkspaceBytes,
          });
          throw observerError(
            `Normal-UI ${phase} observed a conflicting signed extension identity`,
            diagnostic,
          );
        }
        if (stage.isSatisfied(proof)) {
          stageReceipt.completedAt = new Date().toISOString();
          break;
        }
        const remainingMs = deadlineMs - Date.now();
        if (remainingMs <= 0) {
          const diagnostic = phaseDiagnostic({
            phase,
            paths,
            observer,
            proof,
            beforeProfileSettingsBytes,
            beforeWorkspaceBytes,
            observedProfileSettingsBytes:
              observation.observedProfileSettingsBytes,
            observedWorkspaceBytes: observation.observedWorkspaceBytes,
          });
          throw observerError(
            `Timed out in normal-UI ${phase} stage ${stage.label}`,
            diagnostic,
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
