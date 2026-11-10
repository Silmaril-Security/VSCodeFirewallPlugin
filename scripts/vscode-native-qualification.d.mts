export const SAFE_BLOCK_MESSAGE: string;

export function byteReceipt(value: string): {
  byteLength: number;
  sha256: string;
  utf8Hex: string;
};

export function collectStrings(value: unknown, output?: string[]): string[];

export function inspectProviderJournal(filePath: string): Promise<{
  path: string;
  sha256: string;
  byteLength: number;
  integrity: "pass" | "fail";
  validRecordCount: number;
  records: Array<Record<string, any>>;
  errors: Array<{ line: number; message: string }>;
  partialTrailingLine?: {
    byteLength: number;
    sha256: string;
    base64: string;
  };
}>;

export function validateProviderJournalCapture(
  journal: Record<string, any>,
  capture: Record<string, any>,
): {
  result: "pass";
  providerRequestCount: number;
  toolInvocations: Record<string, number>;
};

export function createQualificationCoverage(): {
  nativeCore: {
    scope: "four-case-only";
    caseCount: 4;
    result: "not-run" | "fail" | "pass";
  };
  releaseQualification: {
    result: "incomplete";
    qualifiedForPublication: false;
  };
  batchResume: {
    result: "unsupported";
  };
  nativeWarnShadow: {
    result: "unassessed";
  };
  sharedRoute: {
    result: "unverified" | "verified";
    runtime?: "copilot";
    callbacks?: {
      userPromptTransformed: 4;
      preToolUse: 1;
      postToolUse: 1;
    };
  };
};

export function validateSharedCallbackRoutes(
  classifierRequests: Array<{
    body: {
      hook?: unknown;
      metadata?: {
        vscodeHookRuntime?: unknown;
        vscodeHookEvent?: unknown;
      };
      [key: string]: unknown;
    };
    [key: string]: unknown;
  }>,
): {
  result: "verified";
  runtime: "copilot";
  callbacks: {
    userPromptTransformed: 4;
    preToolUse: 1;
    postToolUse: 1;
  };
};

export function validateQaToolManifest(manifest: Record<string, any>): {
  result: "pass";
  tools: Array<{
    name: string;
    toolReferenceName: string;
    canBeReferencedInPrompt: true;
  }>;
  reviewedOfficialSource: {
    repository: string;
    commit: string;
    paths: string[];
  };
};

export function pathIsWithin(root: string, candidate: string): boolean;

export function resolvePortableQaPolicy(env?: Record<string, string | undefined>): {
  mode: "preflight" | "human-ui";
  allowLaunch: boolean;
  allowNormalTrustHandoff: boolean;
  allowUiEnableHandoff: boolean;
  handoffs: {
    trust?: string;
    disableAi?: string;
    workspaceAi?: string;
  };
};

export function createFreshQaLayout(options: {
  privateRoot: string;
  receiptPath: string;
  policy: ReturnType<typeof resolvePortableQaPolicy>;
}): Promise<{
  root: string;
  receiptPath: string;
  home: string;
  userData: string;
  extensions: string;
  workspace: string;
  temporary: string;
  evidence: string;
  candidate: string;
  workspaceFile: string;
}>;

export function buildMinimalChildEnvironment(
  source: Record<string, string | undefined>,
  overrides: Record<string, string>,
): Record<string, string>;

export function inspectNativeCjsMissingIdentifiers(options?: {
  sourceOverrides?: Record<string, string>;
}): Array<{
  code: number;
  file: string;
  line: number;
  column: number;
  message: string;
}>;

export function inspectAndArchiveFreshUiFiles(options: {
  activeSettingsBytes: Uint8Array;
  activeConfigBytes: Uint8Array;
  originalWorkspaceBytes: Uint8Array;
  observedSettingsBytes: Uint8Array;
  observedConfigBytes: Uint8Array;
  observedWorkspaceBytes: Uint8Array;
  archiveDirectory: string;
}): Promise<{
  classification: Record<string, any>;
  archives: Record<string, { path: string; sha256: string }>;
}>;

export function restoreFreshProfileFiles(options: {
  ownedProfileRoot: string;
  settingsPath: string;
  settingsBytes: Uint8Array;
  configPath: string;
  configBytes: Uint8Array;
  workspaceFilePath: string;
  workspaceFileBytes: Uint8Array;
}): Promise<{
  settingsSha256: string;
  configSha256: string;
  workspaceSha256: string;
  byteExact: boolean;
}>;

export function finalizeQualificationOutcome(options: {
  receipt: Record<string, any>;
  failure?: unknown;
  ownedServersClosed: boolean;
  ownedProcessSettled: boolean;
}): unknown;

export function writeFinalQualificationReceipt(options: {
  receiptPath: string;
  receipt: Record<string, any>;
  failure?: unknown;
  ownedServersClosed: boolean;
  ownedProcessSettled: boolean;
}): Promise<Record<string, any>>;

export function inspectCandidate(destination: string): Promise<{
  version: string;
  files: string[];
  runtimeSha256: string;
  manifestSha256: string;
}>;

export function buildNativeLaunchArgs(options: {
  workspaceFile: string;
  userData: string;
  extensions: string;
  proxyUrl: string;
}): string[];

export function closeServer(
  server: {
    close(callback: (error?: Error) => void): void;
    closeAllConnections?: () => void;
  },
  sockets?: Set<{ destroy(): void }>,
  timeoutMs?: number,
): Promise<void>;

export function startClassifier(options?: {
  closeTimeoutMs?: number;
}): {
  requests: Array<Record<string, any>>;
  open(): Promise<string>;
  close(): Promise<void>;
};

export function startDestinationProxy(options?: {
  connectFactory?: (target: {
    host: string;
    port: number;
  }) => {
    once(event: string, listener: (...args: any[]) => void): unknown;
    pipe(destination: unknown): unknown;
    write(value: unknown): unknown;
    destroy(): void;
    destroyed: boolean;
  };
  closeTimeoutMs?: number;
}): {
  destinations: Array<Record<string, any>>;
  open(): Promise<string>;
  close(): Promise<void>;
};

export function terminateOwnedProcessGroup(pid: number): Promise<void>;

export function ownedProcessGroupExists(pid: number): Promise<boolean>;

export function waitForOwnedProcessGroupAbsence(
  pid: number,
  timeoutMs?: number,
): Promise<void>;

export function settleOwnedProcessGroup(
  processReceipt: Record<string, any>,
  dependencies?: {
    groupExists?: (pid: number) => Promise<boolean>;
    terminateGroup?: (pid: number) => Promise<void>;
  },
): Promise<{
  result: "not-launched" | "pass";
  pid?: number;
  processGroupId?: number;
  presentBeforeCleanup?: boolean;
  terminationAttempted: boolean;
  groupAbsent: true;
}>;

export function waitForOwnedProcessGroup(
  pid: number,
  timeoutMs?: number,
): Promise<{
  pid: number;
  processGroupId: number;
}>;

export function inspectSourceContracts(sources: {
  api: string;
  copilot: string;
  workbench: string;
  agentHost: string;
}): {
  stableLanguageModelProvider: boolean;
  scenarioAutomation: boolean;
  chatOpenDriver: boolean;
  pluginLocations: boolean;
  transformedHook: boolean;
  preToolHook: boolean;
  postToolHook: boolean;
};

export function inspectNormalUiAgentEnablement(sources: {
  workbench: string;
  nlsMessages: string[];
}): {
  standardExtensionsUiComposite: boolean;
  genericEnableActionsExcludeChat: boolean;
  migrationDisablesIncompleteChat: boolean;
  globalAiEnableIsConfigurationOnly: boolean;
  workspaceAiEnableRequiresDisabledSetting: boolean;
  disableAiSetsProfileConfiguration: boolean;
  dynamicRegistrationOnEnablementChange: boolean;
  twoPhaseLabels: boolean;
  noAccountInstallOrTermsInActions: boolean;
};

export function inspectSecretStorageIsolation(sources: {
  main: string;
  shared: string;
  workbench: string;
  extensionHost: string;
  githubAuth: string;
}): {
  mainFlag: boolean;
  sharedArguments: boolean;
  nativeInMemoryService: boolean;
  extensionHostSecretProxy: boolean;
  githubAuthenticationSecretApi: boolean;
};

export function inspectSecretStorageRuntimeLogs(logs: {
  mainLog: string;
  combinedLogs: string;
}): {
  launchFlagSelected: boolean;
  inMemoryServiceSelected: boolean;
  osEncryptionProbeObserved: boolean;
};
