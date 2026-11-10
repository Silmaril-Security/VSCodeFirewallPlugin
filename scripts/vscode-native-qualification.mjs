import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  constants as fsConstants,
  access,
  chmod,
  copyFile,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  readlink,
  realpath,
  stat,
  writeFile,
} from "node:fs/promises";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildMinimalChildEnvironment,
  createFreshQaLayout,
  pathIsWithin,
  resolvePortableQaPolicy,
} from "./vscode-native-fresh-profile.mjs";

export {
  buildMinimalChildEnvironment,
  createFreshQaLayout,
  pathIsWithin,
  resolvePortableQaPolicy,
} from "./vscode-native-fresh-profile.mjs";

const require = createRequire(import.meta.url);
const { classifyFreshProfileUiFiles } = require(
  "../qa/vscode-native/extension/agent-ui-policy.cjs",
);
const { parseProviderJournalBytes } = require(
  "../qa/vscode-native/extension/provider-journal.cjs",
);
const typescript = require("typescript");

export const SAFE_BLOCK_MESSAGE =
  "Silmaril Firewall blocked potentially malicious content.";
export const EXPECTED_APPS = Object.freeze({
  "1.141.1": {
    commit: "7baac39ec3ca969dab74ac12c097f6a486e46593",
    copilotVersion: "0.69.0",
  },
  "1.145.2": {
    commit: "c4453f8ea430795f941c1b2ff6c9321135a74a02",
    copilotVersion: "0.73.0",
  },
});

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(SCRIPT_DIRECTORY, "..");
const QA_EXTENSION = path.join(REPOSITORY_ROOT, "qa", "vscode-native", "extension");
const RUNTIME_FILES = [
  "dist/vscode-hook.js",
  "scripts/run-hook.sh",
  "package.json",
  "plugin.json",
  "com.github.copilot/hooks/hooks.json",
];
const SOURCE_FILES = {
  product: "Contents/Resources/app/product.json",
  api: "Contents/Resources/app/out/vscode-dts/vscode.d.ts",
  copilotManifest: "Contents/Resources/app/extensions/copilot/package.json",
  copilot: "Contents/Resources/app/extensions/copilot/dist/extension.js",
  main: "Contents/Resources/app/out/mainImpl.js",
  shared:
    "Contents/Resources/app/out/vs/code/electron-utility/sharedProcess/sharedProcessMain.js",
  workbench: "Contents/Resources/app/out/vs/workbench/workbench.desktop.main.js",
  extensionHost:
    "Contents/Resources/app/out/vs/workbench/api/node/extensionHostProcess.js",
  githubAuth:
    "Contents/Resources/app/extensions/github-authentication/dist/extension.js",
  agentHost:
    "Contents/Resources/app/out/vs/platform/agentHost/node/agentHostMain.js",
};
const FORBIDDEN_AUTH_ENV = [
  "VSCODE_COPILOT_CHAT_TOKEN",
  "GITHUB_PAT",
  "GITHUB_OAUTH_TOKEN",
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "COPILOT_TOKEN",
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "GOOGLE_API_KEY",
  "GEMINI_API_KEY",
  "XAI_API_KEY",
];
const FORBIDDEN_MODEL_DESTINATIONS = [
  "api.githubcopilot.com",
  "copilot-proxy.githubusercontent.com",
  "api.openai.com",
  "api.anthropic.com",
  "generativelanguage.googleapis.com",
  "api.x.ai",
];
const EXPECTED_TEAM_ID = "UBF8T346G9";
const PROCESS_TIMEOUT_MS = 300_000;
const TRUST_READY_TIMEOUT_MS = 45_000;
const AI_DISABLE_READY_TIMEOUT_MS = 225_000;
const WORKSPACE_AI_ENABLE_READY_TIMEOUT_MS = 420_000;
const UI_HANDOFF_PROCESS_TIMEOUT_MS = 600_000;
const NLS_MESSAGES_SHA256 =
  "1af4ad8ce9493fa8c06047b1924c5569b68f3e1f8f108979422a42e38b9376c7";
const UI_WORKBENCH_SHA256 =
  "8bd0d70cda8542f514a45534a14860ea48ddf39f149036838aebfcf2cc6ba02a";
const COPILOT_MANIFEST_SHA256 =
  "d0e92ec15928120112abbe0d45ce3b4a3c1051562421044848ee3dee014f0874";
const COPILOT_SOURCE_SHA256 =
  "e8db5deec0a8fda393769d44c5f99ec29bd687f4e0e05f6b36e99e606f6efed0";
const SHARED_ROUTE_SOURCE_SHA256 = Object.freeze({
  product: "de4e360bfab7ab5f8cc79590998139da9b73ce5797213327da0ecf3e3e300b0c",
  api: "1100202846278445e33f466d04d98378408da78cb9a4ec0c941ccecba75b769a",
  workbench: "8bd0d70cda8542f514a45534a14860ea48ddf39f149036838aebfcf2cc6ba02a",
  agentHost: "746ceacfdce1ac28d6fed9458e951b379f500a067185c7d92a7d30974c957fc6",
  copilot: "e8db5deec0a8fda393769d44c5f99ec29bd687f4e0e05f6b36e99e606f6efed0",
});
const SHARED_ROUTE_SOURCE_OFFSETS = Object.freeze([
  ["product", "c4453f8ea430795f941c1b2ff6c9321135a74a02", 71833],
  ["api", "registerLanguageModelChatProvider", 740832],
  ["workbench", "byokModelIdentifier", 4142664],
  ["workbench", "function qDe(", 4124168],
  ["workbench", "function EEt(", 4124983],
  ["workbench", "function Fvi(", 6337692],
  ["workbench", "targetChatSessionType?Mk", 9694557],
  ["workbench", "function FDo(", 10064814],
  ["workbench", "id:pf,title:F(13116", 13479537],
  ["agentHost", "onUserPromptTransformed", 812501],
  ["agentHost", "http://127.0.0.1:", 1669985],
  ["agentHost", "No renderer connection available to service BYOK models", 1682898],
  ["agentHost", "providerBaseUrl(", 1842046],
  ["agentHost", "resolveByokSessionConfig", 1852831],
  ["agentHost", "_byokLmProxyService.start", 1853109],
  ["agentHost", "_pendingClientToolCalls.respondOrBuffer", 2097318],
  ["agentHost", "this._wrapper.session.send({prompt:", 2139594],
  ["agentHost", "default:Do.quality!==\"stable\"?\"activeAgent\":\"utility\"", 3666443],
  ["copilot", "executePostToolUseHook", 12394122]
]);
const SHARED_TITLE_SETTING =
  "chat.agentHost.experimental.titleGeneration";
const SHARED_SESSION_TYPE = "agent-host-copilotcli";
const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const REQUIRED_QA_TOOL_IDS = Object.freeze([
  "silmaril_native_qa_preblock_8d724ae7",
  "silmaril_native_qa_posttool_8d724ae7",
]);
const QA_TOOL_REFERENCE_PATTERN = /^[\w-]+$/u;
const QA_TOOL_SELECTION_COMMIT =
  "c4453f8ea430795f941c1b2ff6c9321135a74a02";
const QA_TOOL_SELECTION_SOURCE_PATHS = Object.freeze([
  "src/vs/workbench/contrib/chat/browser/actions/chatActions.ts",
  "src/vs/workbench/contrib/chat/browser/widget/input/chatSelectedTools.ts",
  "src/vs/workbench/contrib/chat/common/tools/languageModelToolsContribution.ts",
  "extensions/copilot/src/extension/tools/vscode-node/toolsService.ts",
]);

export function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function validateQaToolManifest(manifest) {
  assert.equal(manifest?.name, "silmaril-vscode-native-qa");
  const tools = manifest?.contributes?.languageModelTools;
  assert.ok(Array.isArray(tools), "QA manifest must contribute language model tools");
  assert.equal(
    tools.length,
    REQUIRED_QA_TOOL_IDS.length,
    "QA manifest must contain exactly the two reviewed synthetic tools",
  );
  assert.deepEqual(
    tools.map((tool) => tool.name).sort(),
    [...REQUIRED_QA_TOOL_IDS].sort(),
    "QA manifest synthetic tool IDs changed",
  );

  const references = new Set();
  for (const tool of tools) {
    assert.equal(
      tool.canBeReferencedInPrompt,
      true,
      `QA tool ${tool.name} must set canBeReferencedInPrompt=true`,
    );
    assert.equal(
      typeof tool.toolReferenceName,
      "string",
      `QA tool ${tool.name} must provide toolReferenceName`,
    );
    assert.match(
      tool.toolReferenceName,
      QA_TOOL_REFERENCE_PATTERN,
      `QA tool ${tool.name} has an invalid toolReferenceName`,
    );
    assert.equal(
      references.has(tool.toolReferenceName),
      false,
      `QA toolReferenceName must be unique: ${tool.toolReferenceName}`,
    );
    references.add(tool.toolReferenceName);
    assert.equal(
      tool.toolReferenceName,
      tool.name,
      `QA tool ${tool.name} toolReferenceName must equal its existing unique ID`,
    );
    assert.equal(typeof tool.modelDescription, "string");
    assert.ok(tool.modelDescription.length > 0);
    assert.equal(tool.inputSchema?.type, "object");
  }

  return {
    result: "pass",
    tools: tools.map((tool) => ({
      name: tool.name,
      toolReferenceName: tool.toolReferenceName,
      canBeReferencedInPrompt: tool.canBeReferencedInPrompt,
    })),
    reviewedOfficialSource: {
      repository: "https://github.com/microsoft/vscode",
      commit: QA_TOOL_SELECTION_COMMIT,
      paths: QA_TOOL_SELECTION_SOURCE_PATHS.map((sourcePath) =>
        `https://github.com/microsoft/vscode/blob/${QA_TOOL_SELECTION_COMMIT}/${sourcePath}`),
    },
  };
}

export function byteReceipt(value) {
  const bytes = Buffer.from(value, "utf8");
  return {
    byteLength: bytes.byteLength,
    sha256: sha256Bytes(bytes),
    utf8Hex: bytes.toString("hex"),
  };
}

export function collectStrings(value, output = []) {
  if (typeof value === "string") {
    output.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, output);
  } else if (value && typeof value === "object") {
    for (const item of Object.values(value)) collectStrings(item, output);
  }
  return output;
}

const MISSING_IDENTIFIER_DIAGNOSTIC_CODES = new Set([
  2304,
  2552,
  18004,
]);

function nativeCjsFiles() {
  return typescript.sys.readDirectory(
    QA_EXTENSION,
    [".cjs"],
    undefined,
    ["*.cjs"],
  ).map((filePath) => path.resolve(filePath)).sort();
}

export function inspectNativeCjsMissingIdentifiers({
  sourceOverrides = {},
} = {}) {
  const options = {
    allowJs: true,
    checkJs: true,
    noEmit: true,
    strict: false,
    skipLibCheck: true,
    target: typescript.ScriptTarget.ES2022,
    module: typescript.ModuleKind.NodeNext,
    moduleResolution: typescript.ModuleResolutionKind.NodeNext,
    types: ["node"],
  };
  const overrides = new Map(
    Object.entries(sourceOverrides).map(([filePath, source]) => [
      path.resolve(filePath),
      source,
    ]),
  );
  const host = typescript.createCompilerHost(options);
  const getSourceFile = host.getSourceFile.bind(host);
  host.getSourceFile = (
    fileName,
    languageVersion,
    onError,
    shouldCreateNewSourceFile,
  ) => {
    const override = overrides.get(path.resolve(fileName));
    if (override !== undefined) {
      return typescript.createSourceFile(
        fileName,
        override,
        languageVersion,
        true,
        typescript.ScriptKind.JS,
      );
    }
    return getSourceFile(
      fileName,
      languageVersion,
      onError,
      shouldCreateNewSourceFile,
    );
  };
  const program = typescript.createProgram({
    rootNames: nativeCjsFiles(),
    options,
    host,
  });
  return typescript.getPreEmitDiagnostics(program)
    .filter((diagnostic) =>
      MISSING_IDENTIFIER_DIAGNOSTIC_CODES.has(diagnostic.code)
      && diagnostic.file
      && pathIsWithin(QA_EXTENSION, diagnostic.file.fileName))
    .map((diagnostic) => {
      const position = diagnostic.file.getLineAndCharacterOfPosition(
        diagnostic.start ?? 0,
      );
      return {
        code: diagnostic.code,
        file: path.relative(QA_EXTENSION, diagnostic.file.fileName),
        line: position.line + 1,
        column: position.character + 1,
        message: typescript.flattenDiagnosticMessageText(
          diagnostic.messageText,
          "\n",
        ),
      };
    });
}

export function inspectSourceContracts({ api, copilot, workbench, agentHost }) {
  return {
    stableLanguageModelProvider:
      api.includes("interface LanguageModelChatProvider")
      && api.includes("registerLanguageModelChatProvider"),
    scenarioAutomation:
      copilot.includes('IS_SCENARIO_AUTOMATION==="1"')
      && copilot.includes("ScenarioAutomation: using BYOK model")
      && copilot.includes("lm.selectChatModels()")
      && copilot.includes("tokenNoAuthURL"),
    chatOpenDriver:
      workbench.includes('"workbench.action.chat.open"')
      && workbench.includes("modelSelector")
      && workbench.includes("toolsInclude")
      && workbench.includes("blockOnResponse"),
    pluginLocations:
      workbench.includes('"chat.pluginLocations"')
      && workbench.includes("ConfiguredAgentPluginDiscovery"),
    transformedHook:
      agentHost.includes('userPromptTransformed:"UserPromptTransformed"')
      && agentHost.includes("onUserPromptTransformed")
      && agentHost.includes("modifiedTransformedPrompt"),
    preToolHook:
      agentHost.includes('preToolUse:"PreToolUse"')
      && agentHost.includes("onPreToolUse")
      && agentHost.includes("permissionDecision"),
    postToolHook:
      agentHost.includes('postToolUse:"PostToolUse"')
      && agentHost.includes("onPostToolUse")
      && agentHost.includes("modifiedResult"),
  };
}

export function inspectSharedRouteSourceContracts({ workbench, agentHost }) {
  return {
    targetChatSessionTypeTelemetry:
      workbench.includes(
        "a?.targetChatSessionType?Mk(a.targetChatSessionType,i):void 0",
      )
      && workbench.includes("byokModelIdentifier"),
    wrappedModelSessionTypeFiltering:
      workbench.includes(
        'function FDo(s,o,e,t){return o&&o!=="local"&&dXe(s,o)?s.filter(i=>i.metadata?.targetChatSessionType===o',
      )
      && workbench.includes(
        "s.filter(i=>!i.metadata?.targetChatSessionType",
      ),
    visibleNewChatCurrentSessionForwarding:
      workbench.includes(
        "function Fvi(s,o,e){let t=s.get(fi),i=o.viewModel?.model.sessionResource,n=i?ui(i):void 0,r=EEt(s,{explicitOverride:e,currentSessionType:n})",
      )
      && workbench.includes(
        "n?.currentSessionType&&Vci(n.currentSessionType",
      )
      && workbench.includes("function EEt(s,o)")
      && workbench.includes("return qDe(e,t,i,n,a,o,c"),
    visibleNewChatAction:
      workbench.includes('id:pf,title:F(13116,"New Chat")'),
    copilotSdkSend:
      agentHost.includes("this._wrapper.session.send({prompt:"),
    clientToolBridge:
      agentHost.includes("_pendingClientToolCalls.respondOrBuffer")
      && agentHost.includes('type:"chat/toolCallStart"'),
    hookConverters:
      agentHost.includes("onUserPromptTransformed")
      && agentHost.includes(
        "toolResult:{...p.toolResult,...g.modifiedResult}",
      ),
    titleGenerationDeclaration:
      agentHost.includes(
        'enum:[...Cx],enumDescriptions:[m(2794,null),m(2792,null),m(2793,null)]',
      )
      && agentHost.includes(
        'default:Do.quality!=="stable"?"activeAgent":"utility",scope:1',
      )
      && agentHost.includes('o=>o==="activeAgent"')
      && agentHost.includes('o=>o==="agentReview"'),
    titleGenerationNewSessionLogic:
      agentHost.includes("getAutomaticTitleGenerationStrategy")
      && agentHost.includes("_unpersistedTitleStrategies"),
    byokProviderLoopbackConfiguration:
      agentHost.includes(
        'type:"openai",wireApi:"responses",baseUrl:s.providerBaseUrl(l)',
      ),
    byokLocalhostBinding:
      agentHost.includes('r.listen(0,"127.0.0.1"')
      && agentHost.includes("http://127.0.0.1:"),
    byokRendererRequired:
      agentHost.includes("this._bridgeRegistry.getServingConnection()")
      && agentHost.includes(
        '_writeJsonError(t,503,"No renderer connection available to service BYOK models"',
      ),
    byokRegistryChatBridge:
      agentHost.includes("let I=await y.chat(h)")
      && agentHost.includes("resolveByokSessionConfig")
      && agentHost.includes("_byokLmBridgeRegistry")
      && agentHost.includes("_byokLmProxyService.start"),
  };
}

export function inspectNormalUiAgentEnablement({ workbench, nlsMessages }) {
  const actionSource = (id, nextId) => {
    const start = workbench.indexOf(`static{this.ID="${id}"}`);
    const end = workbench.indexOf(`static{this.ID="${nextId}"}`, start);
    return start >= 0 && end > start ? workbench.slice(start, end) : "";
  };
  const enableForWorkspace = actionSource(
    "extensions.enableForWorkspace",
    "extensions.enableGlobally",
  );
  const enableGlobally = actionSource(
    "extensions.enableGlobally",
    "extensions.disableForWorkspace",
  );
  const enableAiGlobally = actionSource(
    "extensions.enableAIGlobally",
    "extensions.enableAIInWorkspace",
  );
  const enableAiInWorkspace = actionSource(
    "extensions.enableAIInWorkspace",
    "extensions.disableAIGlobally",
  );
  const disableAiGlobally = actionSource(
    "extensions.disableAIGlobally",
    "extensions.disableAIInWorkspace",
  );
  const migrationStart = workbench.indexOf(
    "ensureChatExtensionInitialDisabledState(){",
  );
  const migrationEnd = workbench.indexOf(
    "}get hasWorkspace(){",
    migrationStart,
  );
  const migrationSource =
    migrationStart >= 0 && migrationEnd > migrationStart
      ? workbench.slice(migrationStart, migrationEnd)
      : "";
  const dynamicLog = workbench.indexOf(
    "AbstractExtensionService.onEnablementChanged fired",
  );
  const dynamicSourceStart = workbench.lastIndexOf(
    "this._extensionEnablementService.onEnablementChanged",
    dynamicLog,
  );
  const dynamicSource = dynamicSourceStart >= 0
    ? workbench.slice(dynamicSourceStart, dynamicLog + 2000)
    : "";
  const normalActions = [
    enableAiGlobally,
    enableAiInWorkspace,
    disableAiGlobally,
  ].join("\n");
  return {
    standardExtensionsUiComposite:
      workbench.includes('super("extensions.enable",dc.LABEL_ACTION_CLASS'),
    genericEnableActionsExcludeChat:
      enableForWorkspace.includes(
        "defaultChatAgent?.chatExtensionId))return",
      )
      && enableGlobally.includes(
        "defaultChatAgent?.chatExtensionId))return",
      ),
    migrationDisablesIncompleteChat:
      migrationSource.includes(
        "Disabling builtin chat extension as chat set up is not completed",
      )
      && migrationSource.includes(
        "this._disableExtension({id:this._chatExtensionId})",
      ),
    globalAiEnableIsConfigurationOnly:
      enableAiGlobally.includes("this.enabled=e.value===!0")
      && enableAiGlobally.includes(
        "this.configurationService.updateValue(mc,!1)",
      )
      && !enableAiGlobally.includes("setEnablement("),
    workspaceAiEnableRequiresDisabledSetting:
      enableAiInWorkspace.includes("if(e.value!==!1)")
      && enableAiInWorkspace.includes(
        "setEnablement(this.extension,13)",
      )
      && enableAiInWorkspace.includes(
        "this.configurationService.updateValue(mc,!1,5)",
      ),
    disableAiSetsProfileConfiguration:
      disableAiGlobally.includes(
        "this.configurationService.getValue(mc)!==!0",
      )
      && disableAiGlobally.includes(
        "this.configurationService.updateValue(mc,!0)",
      )
      && !disableAiGlobally.includes("setEnablement("),
    dynamicRegistrationOnEnablementChange:
      dynamicSource.includes(
        "this._extensionEnablementService.onEnablementChanged",
      )
      && dynamicSource.includes(
        "AbstractExtensionService.onEnablementChanged fired",
      )
      && dynamicSource.includes("this._handleDeltaExtensions")
      && workbench.includes(
        "this._onDidChangeExtensions.fire({added:r,removed:n})",
      ),
    twoPhaseLabels:
      nlsMessages.includes("Disable AI Features")
      && nlsMessages.includes("Enable AI Features (Workspace)")
      && nlsMessages.includes("Enable AI features in this workspace"),
    noAccountInstallOrTermsInActions:
      !/\b(?:signIn|install|authentication|entitlement|terms)\b/iu.test(
        normalActions,
      ),
  };
}

export function inspectSecretStorageIsolation({
  main,
  shared,
  workbench,
  extensionHost,
  githubAuth,
}) {
  return {
    mainFlag:
      main.includes('"use-inmemory-secretstorage":{type:"boolean"')
      && main.includes(
        'get useInMemorySecretStorage(){return!!this.args["use-inmemory-secretstorage"]}',
      ),
    sharedArguments:
      shared.includes("this.configuration.args")
      && shared.includes(
        'get useInMemorySecretStorage(){return!!this.args["use-inmemory-secretstorage"]}',
      ),
    nativeInMemoryService:
      workbench.includes("super(!!r.useInMemorySecretStorage")
      && workbench.includes(
        "if(!this._useInMemoryStorage&&await this._encryptionService.isEncryptionAvailable())",
      )
      && workbench.includes('this._type="in-memory"'),
    extensionHostSecretProxy:
      extensionHost.includes("getProxy(H.MainThreadSecretState)")
      && extensionHost.includes("$getPassword")
      && extensionHost.includes("$setPassword"),
    githubAuthenticationSecretApi:
      githubAuth.includes("this.context.secrets.get(this.serviceId)")
      && githubAuth.includes("this.context.secrets.store(this.serviceId")
      && githubAuth.includes("this.context.secrets.delete(this.serviceId)")
      && githubAuth.includes("Reading sessions from keychain..."),
  };
}

export function inspectSecretStorageRuntimeLogs({ mainLog, combinedLogs }) {
  return {
    launchFlagSelected:
      mainLog.includes('"use-inmemory-secretstorage":true'),
    inMemoryServiceSelected:
      combinedLogs.includes(
        "[SecretStorageService] Encryption is not available, falling back to in-memory storage",
      ),
    osEncryptionProbeObserved:
      combinedLogs.includes(
        "[EncryptionMainService] Checking if encryption is available",
      ),
  };
}

async function sha256File(filePath) {
  const hash = createHash("sha256");
  const handle = await open(filePath, "r");
  try {
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let position = 0;
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
  } finally {
    await handle.close();
  }
  return hash.digest("hex");
}

async function hashTree(root) {
  const hash = createHash("sha256");
  let fileCount = 0;
  let byteCount = 0;
  async function visit(current, relative) {
    const info = await lstat(current);
    if (info.isSymbolicLink()) {
      const target = await readlink(current);
      hash.update(`L\0${relative}\0${target}\0`);
      return;
    }
    if (info.isDirectory()) {
      hash.update(`D\0${relative}\0`);
      const entries = (await readdir(current)).sort();
      for (const entry of entries) {
        await visit(path.join(current, entry), path.join(relative, entry));
      }
      return;
    }
    assert.ok(info.isFile(), `Unsupported app-bundle entry: ${relative}`);
    hash.update(`F\0${relative}\0${info.size}\0`);
    const handle = await open(current, "r");
    try {
      const buffer = Buffer.allocUnsafe(1024 * 1024);
      let position = 0;
      while (true) {
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
        if (bytesRead === 0) break;
        hash.update(buffer.subarray(0, bytesRead));
        position += bytesRead;
      }
    } finally {
      await handle.close();
    }
    hash.update("\0");
    fileCount += 1;
    byteCount += info.size;
  }
  await visit(root, ".");
  return { sha256: hash.digest("hex"), fileCount, byteCount };
}

async function runProcess(command, args, options = {}) {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    const maxBytes = options.maxBytes ?? 4 * 1024 * 1024;
    const append = (chunks, chunk, current) => {
      const next = current + chunk.byteLength;
      if (next <= maxBytes) chunks.push(Buffer.from(chunk));
      return next;
    };
    child.stdout.on("data", (chunk) => {
      stdoutBytes = append(stdout, chunk, stdoutBytes);
    });
    child.stderr.on("data", (chunk) => {
      stderrBytes = append(stderr, chunk, stderrBytes);
    });
    child.once("error", reject);
    child.once("close", (code, signal) => {
      resolve({
        code,
        signal,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        stdoutTruncated: stdoutBytes > maxBytes,
        stderrTruncated: stderrBytes > maxBytes,
      });
    });
  });
}

async function verifyApp(app, privateHome) {
  const code = path.join(app, "Contents", "Resources", "app", "bin", "code");
  const versionResult = await runProcess(code, ["--version"], {
    env: {
      HOME: privateHome,
      PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
    },
  });
  assert.equal(versionResult.code, 0, `code --version failed: ${versionResult.stderr}`);
  const [version, commit, architecture] = versionResult.stdout.trim().split(/\r?\n/u);
  const expected = EXPECTED_APPS[version];
  assert.ok(expected, `Unapproved VS Code version ${version}`);
  assert.equal(commit, expected.commit, `Unexpected commit for VS Code ${version}`);
  assert.equal(architecture, process.arch, "VS Code architecture does not match QA host");

  const verify = await runProcess("/usr/bin/codesign", [
    "--verify",
    "--deep",
    "--strict",
    "--verbose=2",
    app,
  ]);
  assert.equal(verify.code, 0, `codesign verification failed: ${verify.stderr}`);
  const details = await runProcess("/usr/bin/codesign", [
    "-dv",
    "--verbose=4",
    app,
  ]);
  assert.equal(details.code, 0, `codesign details failed: ${details.stderr}`);
  assert.match(details.stderr, new RegExp(`TeamIdentifier=${EXPECTED_TEAM_ID}`));
  assert.match(
    details.stderr,
    /Authority=Developer ID Application: Microsoft Corporation \(UBF8T346G9\)/u,
  );
  const gatekeeper = await runProcess("/usr/sbin/spctl", [
    "-a",
    "-vv",
    "-t",
    "execute",
    app,
  ]);
  assert.equal(gatekeeper.code, 0, `Gatekeeper rejected app: ${gatekeeper.stderr}`);
  assert.match(gatekeeper.stderr, /source=Notarized Developer ID/u);

  return {
    version,
    commit,
    architecture,
    versionOutput: versionResult.stdout.trim(),
    teamIdentifier: EXPECTED_TEAM_ID,
    codesignDetailsSha256: sha256Bytes(details.stderr),
    gatekeeperOutput: gatekeeper.stderr.trim(),
  };
}

async function sourceReceipt(app, identity) {
  const encoded = {};
  const hashes = {};
  for (const [name, relative] of Object.entries(SOURCE_FILES)) {
    const absolute = path.join(app, relative);
    encoded[name] = await readFile(absolute, "utf8");
    hashes[name] = await sha256File(absolute);
  }
  const nlsMessagesPath = path.join(
    app,
    "Contents/Resources/app/out/nls.messages.json",
  );
  const nlsMessages = JSON.parse(await readFile(nlsMessagesPath, "utf8"));
  const nlsMessagesSha256 = await sha256File(nlsMessagesPath);
  const product = JSON.parse(encoded.product);
  const copilotManifest = JSON.parse(encoded.copilotManifest);
  const copilotExtensionId =
    `${copilotManifest.publisher}.${copilotManifest.name}`.toLowerCase();
  assert.equal(product.version, identity.version);
  assert.equal(product.commit, identity.commit);
  assert.equal(
    copilotManifest.version,
    EXPECTED_APPS[identity.version].copilotVersion,
  );
  assert.equal(copilotManifest.engines?.vscode, `^${identity.version}`);
  assert.equal(
    copilotExtensionId,
    "github.copilot-chat",
    "Signed app has an unexpected built-in Copilot extension identifier",
  );
  assert.ok(
    copilotManifest.contributes?.languageModelChatProviders?.some(
      (entry) => entry.vendor === "copilot",
    ),
    "Bundled Copilot does not contribute its language model provider",
  );
  return {
    hashes,
    sharedRouteReviewedOffsets: SHARED_ROUTE_SOURCE_OFFSETS.map(
      ([name, needle, offset]) => ({
        source: name,
        needle,
        offset,
        exact: Buffer.from(encoded[name], "utf8").indexOf(
          Buffer.from(needle, "utf8"),
        ) === offset,
      }),
    ),
    product: {
      version: product.version,
      commit: product.commit,
      quality: product.quality,
    },
    copilot: {
      id: copilotExtensionId,
      publisher: copilotManifest.publisher,
      name: copilotManifest.name,
      version: copilotManifest.version,
      engine: copilotManifest.engines.vscode,
    },
    contracts: inspectSourceContracts(encoded),
    sharedRouteContracts: inspectSharedRouteSourceContracts(encoded),
    secretStorageIsolation: inspectSecretStorageIsolation(encoded),
    normalUiAgentEnablement: {
      contracts: inspectNormalUiAgentEnablement({
        workbench: encoded.workbench,
        nlsMessages,
      }),
      source: {
        workbenchSha256: hashes.workbench,
        nlsMessagesSha256,
      },
      phases: {
        compositeId: "extensions.enable",
        disable: {
          actionId: "extensions.disableAIGlobally",
          label: "Disable AI Features",
          expectedProfileSetting: {
            key: "chat.disableAIFeatures",
            value: true,
          },
        },
        workspaceEnable: {
          actionId: "extensions.enableAIInWorkspace",
          label: "Enable AI Features (Workspace)",
          tooltip: "Enable AI features in this workspace",
          enablementState: 13,
          expectedWorkspaceSetting: {
            key: "chat.disableAIFeatures",
            value: false,
          },
        },
      },
    },
  };
}

export async function inspectCandidate(destination) {
  const hash = createHash("sha256");
  for (const relative of RUNTIME_FILES) {
    const target = path.join(destination, relative);
    const info = await lstat(target);
    assert.ok(info.isFile() && !info.isSymbolicLink(), `${relative} is not regular`);
    const bytes = await readFile(target);
    hash.update(relative);
    hash.update("\0");
    hash.update(String(bytes.byteLength));
    hash.update("\0");
    hash.update(bytes);
    hash.update("\0");
  }
  const packageJson = JSON.parse(
    await readFile(path.join(destination, "package.json"), "utf8"),
  );
  const pluginJson = JSON.parse(
    await readFile(path.join(destination, "plugin.json"), "utf8"),
  );
  assert.equal(packageJson.version, "0.3.1");
  assert.equal(pluginJson.version, packageJson.version);
  return {
    version: packageJson.version,
    files: RUNTIME_FILES,
    runtimeSha256: hash.digest("hex"),
    manifestSha256: await sha256File(
      path.join(destination, "com.github.copilot", "hooks", "hooks.json"),
    ),
  };
}

async function copyCandidate(destination) {
  for (const relative of RUNTIME_FILES) {
    const source = path.join(REPOSITORY_ROOT, relative);
    const target = path.join(destination, relative);
    const info = await lstat(source);
    assert.ok(info.isFile() && !info.isSymbolicLink(), `${relative} is not regular`);
    await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    await copyFile(source, target, fsConstants.COPYFILE_EXCL);
    if (relative === "scripts/run-hook.sh") await chmod(target, 0o755);
    else await chmod(target, 0o600);
  }
  return await inspectCandidate(destination);
}

async function readJsonRequest(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.byteLength;
    if (size > MAX_REQUEST_BYTES) throw new Error("Classifier request too large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      const address = server.address();
      assert.ok(address && typeof address === "object");
      resolve(address.port);
    });
  });
}

function trackServerSockets(server) {
  const sockets = new Set();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  return sockets;
}

export async function closeServer(server, sockets = new Set(), timeoutMs = 2_000) {
  assert.ok(
    Number.isSafeInteger(timeoutMs) && timeoutMs > 0,
    "Server close timeout must be a positive integer",
  );
  await new Promise((resolve, reject) => {
    let finished = false;
    const finish = (error) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    };
    const timer = setTimeout(() => {
      finish(new Error(`Timed out after ${timeoutMs}ms closing owned server`));
    }, timeoutMs);
    try {
      server.close((error) => finish(error));
      for (const socket of sockets) socket.destroy();
      server.closeAllConnections?.();
    } catch (error) {
      finish(error);
    }
  });
}

export function startClassifier({ closeTimeoutMs = 2_000 } = {}) {
  const requests = [];
  const server = createServer(async (request, response) => {
    try {
      assert.equal(request.socket.remoteAddress, "127.0.0.1");
      assert.equal(request.method, "POST");
      assert.equal(request.url, "/classify");
      const body = await readJsonRequest(request);
      const strings = collectStrings(body);
      const malicious =
        strings.some((value) => value.includes("SILMARIL_NATIVE_BLOCK_8d724ae7"))
        || (body.hook === "tool_call"
          && strings.some((value) => value.includes("SILMARIL_NATIVE_PREBLOCK_8d724ae7")))
        || (body.hook === "tool_response"
          && strings.some((value) => value.includes("SILMARIL_NATIVE_POISON_8d724ae7")));
      requests.push({
        sequence: requests.length + 1,
        body,
        exactText: typeof body.text === "string" ? byteReceipt(body.text) : undefined,
        decision: malicious ? "malicious" : "benign",
      });
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        prediction: malicious ? "MALICIOUS" : "BENIGN",
        score: malicious ? 0.99 : 0.01,
        threshold: 0.5,
        primary_outcome: malicious ? "prompt_injection" : undefined,
      }));
    } catch (error) {
      response.writeHead(500, { "content-type": "application/json" });
      response.end(JSON.stringify({
        error: error instanceof Error ? error.message : String(error),
      }));
    }
  });
  const sockets = trackServerSockets(server);
  let closePromise;
  return {
    requests,
    async open() {
      const port = await listen(server);
      return `http://127.0.0.1:${port}/classify`;
    },
    close() {
      closePromise ??= closeServer(server, sockets, closeTimeoutMs);
      return closePromise;
    },
  };
}

function parseAuthority(authority) {
  const separator = authority.lastIndexOf(":");
  if (separator < 1) return { host: authority, port: 443 };
  return {
    host: authority.slice(0, separator),
    port: Number(authority.slice(separator + 1)),
  };
}

export function startDestinationProxy({
  connectFactory = ({ host, port }) => net.connect(port, host),
  closeTimeoutMs = 2_000,
} = {}) {
  const destinations = [];
  let closing = false;
  const server = createServer((request, response) => {
    destinations.push({
      protocol: "http",
      destination: request.headers.host ?? request.url ?? "unknown",
      allowed: false,
    });
    response.writeHead(403);
    response.end();
  });
  const sockets = trackServerSockets(server);
  server.on("connect", (request, client, head) => {
    const { host, port } = parseAuthority(request.url ?? "");
    const allowed = host === "api.github.com" && port === 443;
    destinations.push({
      protocol: "connect",
      destination: `${host}:${port}`,
      allowed,
    });
    if (!allowed) {
      client.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
      return;
    }
    if (closing) {
      client.destroy();
      return;
    }
    const upstream = connectFactory({ host, port });
    sockets.add(upstream);
    let pairClosed = false;
    const closePair = () => {
      if (pairClosed) return;
      pairClosed = true;
      sockets.delete(upstream);
      if (!client.destroyed) client.destroy();
      if (!upstream.destroyed) upstream.destroy();
    };
    client.once("close", closePair);
    client.once("error", closePair);
    upstream.once("close", closePair);
    upstream.once("error", closePair);
    upstream.once("connect", () => {
      if (closing) {
        closePair();
        return;
      }
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
  });
  let closePromise;
  return {
    destinations,
    async open() {
      const port = await listen(server);
      return `http://127.0.0.1:${port}`;
    },
    close() {
      closing = true;
      closePromise ??= closeServer(server, sockets, closeTimeoutMs);
      return closePromise;
    },
  };
}

async function processIdentity(pid) {
  const result = await runProcess("/bin/ps", [
    "-p",
    String(pid),
    "-o",
    "pid=",
    "-o",
    "lstart=",
    "-o",
    "command=",
  ]);
  return result.stdout.trim();
}

export async function ownedProcessGroupExists(pid) {
  assert.ok(
    Number.isSafeInteger(pid) && pid > 1,
    "Owned process-group PID must be a positive integer greater than one",
  );
  const result = await runProcess("/usr/bin/pgrep", [
    "-g",
    String(pid),
  ]);
  if (result.code === 0) return true;
  if (result.code === 1) return false;
  throw new Error(
    `Unable to inspect owned process group ${pid}: ${result.stderr.trim()}`,
  );
}

export async function waitForOwnedProcessGroupAbsence(pid, timeoutMs = 2_000) {
  assert.ok(
    Number.isSafeInteger(pid) && pid > 1,
    "Owned process-group PID must be a positive integer greater than one",
  );
  assert.ok(
    Number.isSafeInteger(timeoutMs) && timeoutMs > 0,
    "Owned process-group absence timeout must be a positive integer",
  );
  const deadline = Date.now() + timeoutMs;
  do {
    if (!await ownedProcessGroupExists(pid)) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  } while (Date.now() < deadline);
  if (!await ownedProcessGroupExists(pid)) return;
  throw new Error(
    `Owned process group ${pid} remained alive after bounded termination`,
  );
}

export async function waitForOwnedProcessGroup(pid, timeoutMs = 1_000) {
  assert.ok(
    Number.isSafeInteger(pid) && pid > 1,
    "Owned process-group PID must be a positive integer greater than one",
  );
  assert.ok(
    Number.isSafeInteger(timeoutMs) && timeoutMs > 0,
    "Owned process-group timeout must be a positive integer",
  );
  const deadline = Date.now() + timeoutMs;
  let lastIdentity;
  do {
    const result = await runProcess("/bin/ps", [
      "-p",
      String(pid),
      "-o",
      "pid=",
      "-o",
      "pgid=",
    ]);
    const fields = result.stdout.trim().split(/\s+/u);
    if (result.code === 0 && fields.length === 2) {
      lastIdentity = {
        pid: Number(fields[0]),
        processGroupId: Number(fields[1]),
      };
      if (
        lastIdentity.pid === pid
        && lastIdentity.processGroupId === pid
      ) {
        return lastIdentity;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  } while (Date.now() < deadline);
  throw new Error(
    `Detached owned process-group identity was not established for PID ${pid}; last identity ${JSON.stringify(lastIdentity)}`,
  );
}

export async function terminateOwnedProcessGroup(pid) {
  assert.ok(
    Number.isSafeInteger(pid) && pid > 1,
    "Owned process-group PID must be a positive integer greater than one",
  );
  try {
    process.kill(-pid, "SIGTERM");
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
    return;
  }
  const deadline = Date.now() + 2_000;
  while (await ownedProcessGroupExists(pid) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  if (!await ownedProcessGroupExists(pid)) return;
  try {
    process.kill(-pid, "SIGKILL");
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
  await waitForOwnedProcessGroupAbsence(pid);
}

export async function settleOwnedProcessGroup(
  processReceipt,
  {
    groupExists = ownedProcessGroupExists,
    terminateGroup = terminateOwnedProcessGroup,
  } = {},
) {
  const pid = processReceipt?.pid;
  if (!processReceipt || !Object.hasOwn(processReceipt, "pid")) {
    return {
      result: "not-launched",
      groupAbsent: true,
      terminationAttempted: false,
    };
  }
  assert.ok(
    Number.isSafeInteger(pid) && pid > 1,
    "Recorded owned process-group PID is invalid",
  );
  const identity = processReceipt?.processGroupIdentity;
  assert.deepEqual(
    identity,
    { pid, processGroupId: pid },
    "Recorded process does not have a proven detached owned process-group identity",
  );
  const proof = {
    result: "fail",
    pid,
    processGroupId: pid,
    presentBeforeCleanup: undefined,
    terminationAttempted: false,
    groupAbsent: false,
  };
  try {
    proof.presentBeforeCleanup = await groupExists(pid);
    if (proof.presentBeforeCleanup) {
      proof.terminationAttempted = true;
      await terminateGroup(pid);
    }
    proof.groupAbsent = !await groupExists(pid);
    assert.equal(
      proof.groupAbsent,
      true,
      `Owned process group ${pid} is still present after cleanup`,
    );
    proof.result = "pass";
    return proof;
  } catch (error) {
    if (error && typeof error === "object") {
      error.processGroupCleanup = proof;
    }
    throw error;
  }
}

async function recordReadyHandoff({
  readyPath,
  pendingPath,
  pendingContext,
  pendingState,
  readyTimeoutMs,
  readinessDescription,
  pid,
  identityPromise,
  isSettled,
}) {
  const deadline = Date.now() + readyTimeoutMs;
  while (Date.now() < deadline) {
    if (await pathExists(readyPath)) {
      try {
        const ready = JSON.parse(await readFile(readyPath, "utf8"));
        await writeJsonExclusive(pendingPath, {
          schemaVersion: 1,
          state: pendingState,
          recordedAt: new Date().toISOString(),
          ...pendingContext,
          appPID: pid,
          startIdentity: await identityPromise,
          ready,
        });
        return;
      } catch (error) {
        if (!(error instanceof SyntaxError)) throw error;
      }
    }
    if (isSettled()) {
      throw new Error(`VS Code exited before ${readinessDescription} was ready`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out waiting for ${readinessDescription} ready marker`);
}

async function monitorExtensionCapture({
  capturePath,
  isSettled,
  terminateOwned,
}) {
  while (!isSettled()) {
    if (await pathExists(capturePath)) {
      try {
        const capture = JSON.parse(await readFile(capturePath, "utf8"));
        if (capture.result === "fail") {
          await terminateOwned();
          return {
            result: "fail",
            ownedProcessGroupTerminated: true,
            error: capture.error,
          };
        }
        return {
          result: capture.result,
          ownedProcessGroupTerminated: false,
        };
      } catch (error) {
        if (!(error instanceof SyntaxError)) throw error;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  return {
    result: "process-exited-before-extension-capture",
    ownedProcessGroupTerminated: false,
  };
}

async function launchApp({
  executable,
  args,
  cwd,
  env,
  stdoutPath,
  stderrPath,
  handoffs = [],
  capturePath,
  processTimeoutMs = PROCESS_TIMEOUT_MS,
}) {
  const stdout = await open(stdoutPath, "wx", 0o600);
  const stderr = await open(stderrPath, "wx", 0o600);
  return await new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      cwd,
      env,
      detached: true,
      stdio: ["ignore", stdout.fd, stderr.fd],
    });
    let timedOut = false;
    let settled = false;
    let identityPromise = Promise.resolve("");
    let handoffPromise = Promise.resolve();
    let handoffError;
    let handoffCleanupError;
    let parentSignal;
    let parentSignalCleanupError;
    let parentSignalCleanupPromise = Promise.resolve();
    let timeoutCleanupError;
    let timeoutCleanupPromise = Promise.resolve();
    let captureMonitorError;
    let captureMonitorPromise = Promise.resolve({
      result: "not-started",
      ownedProcessGroupTerminated: false,
    });
    const ownershipPromise = typeof child.pid === "number"
      ? waitForOwnedProcessGroup(child.pid).then(
        (identity) => ({ identity }),
        (error) => ({ error }),
      )
      : Promise.resolve({
        error: new Error("Spawn did not assign an owned process PID"),
      });
    const terminateOwned = async () => {
      const ownership = await ownershipPromise;
      if (ownership.error) throw ownership.error;
      await terminateOwnedProcessGroup(ownership.identity.pid);
    };
    const handleParentSignal = (signal) => {
      if (parentSignal) return;
      parentSignal = signal;
      if (typeof child.pid !== "number") return;
      parentSignalCleanupPromise = terminateOwned().catch((error) => {
        parentSignalCleanupError = error;
      });
    };
    const onSigterm = () => handleParentSignal("SIGTERM");
    const onSigint = () => handleParentSignal("SIGINT");
    process.once("SIGTERM", onSigterm);
    process.once("SIGINT", onSigint);
    const removeParentSignalHandlers = () => {
      process.off("SIGTERM", onSigterm);
      process.off("SIGINT", onSigint);
    };
    child.once("spawn", () => {
      identityPromise = processIdentity(child.pid);
      captureMonitorPromise = monitorExtensionCapture({
        capturePath,
        isSettled: () => settled,
        terminateOwned,
      }).catch((error) => {
        captureMonitorError = error;
        return {
          result: "cleanup-error",
          ownedProcessGroupTerminated: false,
        };
      });
      handoffPromise = Promise.all(handoffs.map((handoff) =>
        recordReadyHandoff({
          ...handoff,
          pid: child.pid,
          identityPromise,
          isSettled: () => settled,
        }))).catch(async (error) => {
        handoffError = error;
        try {
          await terminateOwned();
        } catch (cleanupError) {
          handoffCleanupError = cleanupError;
        }
      });
    });
    child.once("error", async (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      removeParentSignalHandlers();
      await Promise.allSettled([stdout.close(), stderr.close()]);
      reject(error);
    });
    const timer = setTimeout(async () => {
      timedOut = true;
      timeoutCleanupPromise = terminateOwned().catch((error) => {
        timeoutCleanupError = error;
      });
      await timeoutCleanupPromise;
    }, processTimeoutMs);
    child.once("close", async (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      removeParentSignalHandlers();
      await handoffPromise;
      const captureCleanup = await captureMonitorPromise;
      await parentSignalCleanupPromise;
      await timeoutCleanupPromise;
      const ownership = await ownershipPromise;
      await Promise.allSettled([stdout.close(), stderr.close()]);
      const processReceipt = {
        pid: child.pid,
        processGroupIdentity: ownership.identity,
        startIdentity: await identityPromise,
        code,
        signal,
        timedOut,
        captureCleanup,
        parentSignal,
      };
      const rejectWithProcessReceipt = (error) => {
        const failure = error instanceof Error
          ? error
          : new Error(String(error));
        failure.processReceipt = processReceipt;
        reject(failure);
      };
      if (handoffError) {
        rejectWithProcessReceipt(handoffCleanupError ?? handoffError);
        return;
      }
      if (parentSignalCleanupError) {
        rejectWithProcessReceipt(parentSignalCleanupError);
        return;
      }
      if (timeoutCleanupError) {
        rejectWithProcessReceipt(timeoutCleanupError);
        return;
      }
      if (captureMonitorError) {
        rejectWithProcessReceipt(captureMonitorError);
        return;
      }
      if (ownership.error) {
        rejectWithProcessReceipt(ownership.error);
        return;
      }
      resolve(processReceipt);
    });
  });
}

async function listEvidence(directory) {
  const entries = await readdir(directory, { withFileTypes: true }).catch((error) => {
    if (error?.code === "ENOENT") return [];
    throw error;
  });
  const evidence = [];
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
    const body = JSON.parse(await readFile(path.join(directory, entry.name), "utf8"));
    evidence.push({
      file: entry.name,
      hook: body.hook,
      prediction: body.prediction,
      mode: body.mode,
      policyDecision: body.policyDecision,
      nativeAction: body.nativeAction,
      evidenceTruth: body.evidenceTruth,
      requestFingerprint: body.requestFingerprint,
    });
  }
  return evidence;
}

export async function inspectProviderJournal(filePath) {
  const bytes = await readFile(filePath);
  return {
    path: filePath,
    sha256: sha256Bytes(bytes),
    byteLength: bytes.byteLength,
    ...parseProviderJournalBytes(bytes),
  };
}

export function validateProviderJournalCapture(journal, capture) {
  assert.equal(journal.integrity, "pass", "Provider journal integrity failed");
  const providerRequests = journal.records
    .filter((record) => record.type === "provider-request")
    .map((record) => record.request);
  assert.deepEqual(
    providerRequests,
    capture.providerRequests,
    "Provider journal does not match the finished provider capture",
  );
  const toolInvocations = Object.fromEntries(
    Object.keys(capture.toolInvocations ?? {}).map((name) => [name, 0]),
  );
  for (const record of journal.records) {
    if (record.type !== "tool-invocation") continue;
    assert.equal(
      Object.hasOwn(toolInvocations, record.toolName),
      true,
      `Provider journal contains unexpected tool ${record.toolName}`,
    );
    assert.equal(
      record.invocationCount,
      toolInvocations[record.toolName] + 1,
      `Provider journal tool count is not contiguous for ${record.toolName}`,
    );
    toolInvocations[record.toolName] = record.invocationCount;
  }
  assert.deepEqual(
    toolInvocations,
    capture.toolInvocations,
    "Provider journal tool counts do not match the finished provider capture",
  );
  return {
    result: "pass",
    providerRequestCount: providerRequests.length,
    toolInvocations,
  };
}

function callbackFor(requests, marker, hook = "user_input") {
  return requests.filter(
    (request) =>
      request.body.hook === hook
      && collectStrings(request.body).some((value) => value.includes(marker)),
  );
}

function requestStrings(request) {
  return collectStrings(request.messages);
}

export function createQualificationCoverage() {
  return {
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
  };
}

export function validateSharedCallbackRoutes(classifierRequests) {
  assert.ok(Array.isArray(classifierRequests));
  const promptCases = [
    "SILMARIL_NATIVE_ALLOW_8d724ae7",
    "SILMARIL_NATIVE_BLOCK_8d724ae7",
    "SILMARIL_NATIVE_PREBLOCK_8d724ae7",
    "SILMARIL_NATIVE_POSTTOOL_8d724ae7",
  ];
  const assertRoute = (request, runtime, event, description) => {
    assert.equal(
      request?.body?.metadata?.vscodeHookRuntime,
      runtime,
      `${description} must use vscodeHookRuntime=${runtime}`,
    );
    assert.equal(
      request?.body?.metadata?.vscodeHookEvent,
      event,
      `${description} must use vscodeHookEvent=${event}`,
    );
  };
  const expectedEvents = new Map([
    ["user_input", "userPromptTransformed"],
    ["tool_call", "preToolUse"],
    ["tool_response", "postToolUse"],
  ]);
  for (const request of classifierRequests) {
    const event = expectedEvents.get(request?.body?.hook);
    assert.ok(event, "Unexpected classifier hook in native core");
    assertRoute(request, "copilot", event, "Observed callback");
  }
  for (const marker of promptCases) {
    const callbacks = callbackFor(classifierRequests, marker);
    assert.equal(
      callbacks.length,
      1,
      `Expected exactly one user_input callback for ${marker}`,
    );
    assertRoute(
      callbacks[0],
      "copilot",
      "userPromptTransformed",
      `Callback for ${marker}`,
    );
  }
  assert.equal(
    classifierRequests.filter((request) => request.body.hook === "user_input").length,
    promptCases.length,
    "Expected exactly four shared transformed user_input callbacks",
  );

  const preToolCallbacks = callbackFor(
    classifierRequests,
    "SILMARIL_NATIVE_PREBLOCK_8d724ae7",
    "tool_call",
  );
  assert.equal(
    preToolCallbacks.length,
    1,
    "Expected exactly one preToolUse tool_call callback",
  );
  assertRoute(
    preToolCallbacks[0],
    "copilot",
    "preToolUse",
    "Pre-tool callback",
  );

  const postToolCallbacks = callbackFor(
    classifierRequests,
    "SILMARIL_NATIVE_POISON_8d724ae7",
    "tool_response",
  );
  assert.equal(
    postToolCallbacks.length,
    1,
    "Expected exactly one postToolUse tool_response callback",
  );
  assertRoute(
    postToolCallbacks[0],
    "copilot",
    "postToolUse",
    "Post-tool callback",
  );

  return {
    result: "verified",
    runtime: "copilot",
    callbacks: {
      userPromptTransformed: promptCases.length,
      preToolUse: 1,
      postToolUse: 1,
    },
  };
}

export function validateSharedExecutionRoute({
  sessionRoute,
  combinedLogs,
  callbackProof,
  capture,
}) {
  assert.equal(
    sessionRoute,
    "shared-copilot",
    "Legacy Local configuration cannot satisfy the shared execution guard",
  );
  assert.equal(callbackProof?.result, "verified");
  assert.equal(callbackProof?.runtime, "copilot");
  assert.equal(
    capture?.sessionRoute?.selectionAttestation?.executionProof,
    false,
    "Visible-selection attestation must remain action-only evidence",
  );
  assert.equal(
    capture?.sessionRoute?.firstTurnEvidence?.source,
    "fresh-profile-renderer-logs",
    "Missing independently recorded first-turn renderer-log evidence",
  );
  assert.equal(
    capture?.sessionRoute?.firstTurnEvidence?.firstTurn?.sessionType,
    SHARED_SESSION_TYPE,
    "First-turn checkpoint did not record the shared session type",
  );
  assert.deepEqual(capture?.sessionRoute?.modelSelector, {
    vendor: SHARED_SESSION_TYPE,
    id:
      "silmaril-native-qa-dummy-8d724ae7/silmaril-native-qa-local-deterministic-8d724ae7",
  });
  assert.equal(
    capture?.sessionRoute?.publicWrappedModel?.vendor,
    SHARED_SESSION_TYPE,
  );
  assert.equal(
    capture?.sessionRoute?.publicWrappedModel?.id,
    capture.sessionRoute.modelSelector.id,
  );
  assert.ok(
    Array.isArray(capture?.providerRequests)
      && capture.providerRequests.length > 0,
    "Shared execution did not reach the deterministic dummy provider",
  );
  for (const request of capture.providerRequests) {
    assert.equal(
      request?.model?.id,
      "silmaril-native-qa-local-deterministic-8d724ae7",
      "A provider request did not reach the registered deterministic dummy",
    );
  }

  const turnRows = [];
  const rowPattern = /\[ChatTTFP\] end (\{[^\n]+\})/gu;
  for (const match of combinedLogs.matchAll(rowPattern)) {
    try {
      const row = JSON.parse(match[1]);
      if (row.interactionKind === "turn") turnRows.push(row);
    } catch {
      // A malformed runtime row cannot become positive route evidence.
    }
  }
  assert.ok(
    turnRows.length >= 4,
    "Missing first-turn and four-case ChatTTFP runtime metadata",
  );
  assert.equal(
    turnRows[0].sessionType,
    SHARED_SESSION_TYPE,
    "First turn did not execute in agent-host-copilotcli",
  );
  assert.equal(
    turnRows.every((row) => row.sessionType === SHARED_SESSION_TYPE),
    true,
    "Mixed or Local ChatTTFP session metadata observed",
  );

  const resourceSessionTypes = [
    ...combinedLogs.matchAll(/vscode-chat-session:\/\/([^/\s]+)\//gu),
  ].map((match) => match[1]);
  assert.ok(
    resourceSessionTypes.includes(SHARED_SESSION_TYPE),
    "No shared session resource was observed",
  );

  return {
    ...callbackProof,
    execution: "verified",
    sessionType: SHARED_SESSION_TYPE,
    firstTurn: {
      chatSessionId: turnRows[0].chatSessionId,
      sessionType: turnRows[0].sessionType,
      agent: turnRows[0].agent,
      model: turnRows[0].model,
    },
    observedTurnCount: turnRows.length,
    sharedSessionResourceObserved: true,
    selectionAttestationIsExecutionProof: false,
    firstTurnCheckpointObserved: true,
  };
}

function validateNativeEvidence(
  capture,
  classifierRequests,
  preMarkerExists,
  coverage,
  sessionRoute,
  combinedLogs,
) {
  assert.equal(capture.result, "pass", capture.error?.message);
  assert.equal(capture.workspaceTrusted, true);
  assert.equal(preMarkerExists, false, "Pre-tool marker exists");
  const callbackProof = validateSharedCallbackRoutes(classifierRequests);
  coverage.sharedRoute = validateSharedExecutionRoute({
    sessionRoute,
    combinedLogs,
    callbackProof,
    capture,
  });
  const promptCases = [
    "SILMARIL_NATIVE_ALLOW_8d724ae7",
    "SILMARIL_NATIVE_BLOCK_8d724ae7",
    "SILMARIL_NATIVE_PREBLOCK_8d724ae7",
    "SILMARIL_NATIVE_POSTTOOL_8d724ae7",
  ];
  for (const marker of promptCases) {
    assert.equal(
      callbackFor(classifierRequests, marker).length,
      1,
      `Expected one transformed callback and zero submitted duplicate for ${marker}`,
    );
  }
  assert.equal(
    classifierRequests.filter((request) => request.body.hook === "user_input").length,
    4,
    "Shared submitted prompts caused duplicate classification",
  );
  assert.equal(
    callbackFor(
      classifierRequests,
      "SILMARIL_NATIVE_PREBLOCK_8d724ae7",
      "tool_call",
    ).length,
    1,
  );
  assert.equal(
    callbackFor(
      classifierRequests,
      "SILMARIL_NATIVE_POISON_8d724ae7",
      "tool_response",
    ).length,
    1,
  );

  const allowCallback = callbackFor(
    classifierRequests,
    "SILMARIL_NATIVE_ALLOW_8d724ae7",
  )[0];
  assert.equal(allowCallback.decision, "benign");
  assert.ok(
    capture.providerRequests.some((request) =>
      requestStrings(request).includes(allowCallback.body.text)),
    "Exact untrimmed transformed bytes did not reach the dummy provider",
  );

  const blockCallback = callbackFor(
    classifierRequests,
    "SILMARIL_NATIVE_BLOCK_8d724ae7",
  )[0];
  assert.equal(blockCallback.decision, "malicious");
  const allProviderStrings = collectStrings(capture.providerRequests);
  assert.equal(
    allProviderStrings.some((value) =>
      value.includes("SILMARIL_NATIVE_BLOCK_8d724ae7")),
    false,
  );
  assert.ok(allProviderStrings.includes(SAFE_BLOCK_MESSAGE));

  const postRequest = capture.providerRequests.find((request) => {
    const strings = requestStrings(request);
    return strings.some((value) => value.includes("SILMARIL_NATIVE_POSTTOOL_8d724ae7"))
      && strings.includes(SAFE_BLOCK_MESSAGE);
  });
  assert.ok(postRequest, "No next provider request contained the replaced post-tool result");
  assert.equal(
    requestStrings(postRequest).some((value) =>
      value.includes("SILMARIL_NATIVE_POISON_8d724ae7")),
    false,
  );
  assert.equal(
    capture.toolInvocations.silmaril_native_qa_preblock_8d724ae7,
    0,
  );
  assert.equal(
    capture.toolInvocations.silmaril_native_qa_posttool_8d724ae7,
    1,
  );
}

async function writeJson(filePath, value) {
  await mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

async function writeJsonExclusive(filePath, value) {
  await mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
}

async function assertOwnedPathWithin(root, candidate, expectedType) {
  const rootResolved = await realpath(root);
  const info = await lstat(candidate);
  assert.equal(info.isSymbolicLink(), false, `${candidate} must not be a symlink`);
  if (typeof process.getuid === "function") {
    assert.equal(info.uid, process.getuid(), `${candidate} is not owned by this user`);
  }
  if (expectedType === "directory") {
    assert.equal(info.isDirectory(), true, `${candidate} must be a directory`);
  } else {
    assert.equal(info.isFile(), true, `${candidate} must be a regular file`);
  }
  const resolved = await realpath(candidate);
  assert.equal(
    pathIsWithin(rootResolved, resolved),
    true,
    `${candidate} resolves outside the synthetic profile`,
  );
  return resolved;
}

async function listLogDirectoryNames(userData) {
  const logsRoot = path.join(userData, "logs");
  const entries = await readdir(logsRoot, { withFileTypes: true }).catch((error) => {
    if (error?.code === "ENOENT") return [];
    throw error;
  });
  return entries.filter((entry) => entry.isDirectory()).map((entry) => entry.name);
}

async function readCurrentLaunchLogEvidence(userData, logDirectories) {
  const logsRoot = path.join(userData, "logs");
  const files = [];
  const chunks = [];
  const visit = async (directory) => {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(absolute);
      } else if (entry.isFile() && entry.name.endsWith(".log")) {
        const bytes = await readFile(absolute);
        chunks.push(bytes.toString("utf8"));
        files.push({
          relativePath: path.relative(logsRoot, absolute),
          sha256: sha256Bytes(bytes),
          byteLength: bytes.byteLength,
        });
      }
    }
  };
  for (const name of logDirectories) {
    await visit(path.join(logsRoot, name));
  }
  return {
    files,
    combinedLogs: chunks.join("\n"),
  };
}

export async function inspectAndArchiveFreshUiFiles({
  activeSettingsBytes,
  activeConfigBytes,
  originalWorkspaceBytes,
  observedSettingsBytes,
  observedConfigBytes,
  observedWorkspaceBytes,
  archiveDirectory,
}) {
  assert.ok(
    archiveDirectory && path.isAbsolute(archiveDirectory),
    "Fresh UI archive directory must be absolute",
  );
  await mkdir(archiveDirectory, { recursive: true, mode: 0o700 });
  const archives = {};
  for (const [name, details] of Object.entries({
    settings: {
      bytes: Buffer.from(observedSettingsBytes),
      baseline: Buffer.from(activeSettingsBytes),
      file: "profile-settings-observed-before-restoration.json",
    },
    config: {
      bytes: Buffer.from(observedConfigBytes),
      baseline: Buffer.from(activeConfigBytes),
      file: "firewall-config-observed-before-restoration.json",
    },
    workspace: {
      bytes: Buffer.from(observedWorkspaceBytes),
      baseline: Buffer.from(originalWorkspaceBytes),
      file: "workspace-observed-before-restoration.code-workspace",
    },
  })) {
    if (details.bytes.equals(details.baseline)) continue;
    const archivePath = path.join(archiveDirectory, details.file);
    await writeFile(archivePath, details.bytes, {
      flag: "wx",
      mode: 0o600,
    });
    archives[name] = {
      path: archivePath,
      sha256: sha256Bytes(details.bytes),
    };
  }
  let classification;
  try {
    classification = classifyFreshProfileUiFiles({
      activeSettingsBytes,
      activeConfigBytes,
      originalWorkspaceBytes,
      observedSettingsBytes,
      observedConfigBytes,
      observedWorkspaceBytes,
    });
  } catch (error) {
    classification = {
      expected: false,
      parseError: {
        name: error instanceof Error ? error.name : "Error",
        message: error instanceof Error ? error.message : String(error),
      },
    };
  }
  return { classification, archives };
}

export async function restoreFreshProfileFiles({
  ownedProfileRoot,
  settingsPath,
  settingsBytes,
  configPath,
  configBytes,
  workspaceFilePath,
  workspaceFileBytes,
}) {
  assert.ok(
    ownedProfileRoot && path.isAbsolute(ownedProfileRoot),
    "Restoration requires an absolute owned profile root",
  );
  const rootResolved = await assertOwnedPathWithin(
    ownedProfileRoot,
    ownedProfileRoot,
    "directory",
  );
  const specifications = [
    {
      name: "settings",
      candidate: settingsPath,
      bytes: Buffer.from(settingsBytes),
    },
    {
      name: "config",
      candidate: configPath,
      bytes: Buffer.from(configBytes),
    },
    {
      name: "workspace",
      candidate: workspaceFilePath,
      bytes: Buffer.from(workspaceFileBytes),
    },
  ];
  const opened = [];
  const validateOpenedFile = async (entry) => {
    const pathInfo = await lstat(entry.candidate);
    assert.equal(
      pathInfo.isSymbolicLink(),
      false,
      `${entry.candidate} must not be a symlink`,
    );
    assert.equal(
      pathInfo.isFile(),
      true,
      `${entry.candidate} must be a regular file`,
    );
    if (typeof process.getuid === "function") {
      assert.equal(
        pathInfo.uid,
        process.getuid(),
        `${entry.candidate} is not owned by this user`,
      );
    }
    const resolved = await realpath(entry.candidate);
    assert.equal(
      pathIsWithin(rootResolved, resolved),
      true,
      `${entry.candidate} resolves outside the synthetic profile`,
    );
    const handleInfo = await entry.handle.stat();
    assert.equal(
      handleInfo.isFile(),
      true,
      `${entry.candidate} opened as a non-regular file`,
    );
    if (typeof process.getuid === "function") {
      assert.equal(
        handleInfo.uid,
        process.getuid(),
        `${entry.candidate} opened with an unexpected owner`,
      );
    }
    assert.equal(
      handleInfo.dev,
      pathInfo.dev,
      `${entry.candidate} changed device during restoration validation`,
    );
    assert.equal(
      handleInfo.ino,
      pathInfo.ino,
      `${entry.candidate} changed inode during restoration validation`,
    );
  };
  let restorationFailure;
  try {
    for (const specification of specifications) {
      await assertOwnedPathWithin(
        rootResolved,
        specification.candidate,
        "file",
      );
      const handle = await open(
        specification.candidate,
        fsConstants.O_RDWR | fsConstants.O_NOFOLLOW,
      );
      const entry = { ...specification, handle };
      opened.push(entry);
      await validateOpenedFile(entry);
    }
    // Revalidate every pinned handle before the first destructive operation.
    for (const entry of opened) await validateOpenedFile(entry);
    const restoration = { byteExact: false };
    for (const entry of opened) {
      await validateOpenedFile(entry);
      await entry.handle.truncate(0);
      let offset = 0;
      while (offset < entry.bytes.byteLength) {
        const { bytesWritten } = await entry.handle.write(
          entry.bytes,
          offset,
          entry.bytes.byteLength - offset,
          offset,
        );
        assert.ok(bytesWritten > 0, `Unable to restore ${entry.candidate}`);
        offset += bytesWritten;
      }
      await entry.handle.sync();
      const hash = createHash("sha256");
      const buffer = Buffer.allocUnsafe(64 * 1024);
      let position = 0;
      while (true) {
        const { bytesRead } = await entry.handle.read(
          buffer,
          0,
          buffer.byteLength,
          position,
        );
        if (bytesRead === 0) break;
        hash.update(buffer.subarray(0, bytesRead));
        position += bytesRead;
      }
      const actualSha256 = hash.digest("hex");
      assert.equal(actualSha256, sha256Bytes(entry.bytes));
      restoration[`${entry.name}Sha256`] = actualSha256;
    }
    restoration.byteExact = true;
    return restoration;
  } catch (error) {
    restorationFailure = error;
    throw error;
  } finally {
    const closes = await Promise.allSettled(
      opened.map((entry) => entry.handle.close()),
    );
    const closeErrors = closes
      .filter((outcome) => outcome.status === "rejected")
      .map((outcome) => outcome.reason);
    if (closeErrors.length > 0) {
      throw new AggregateError(
        restorationFailure
          ? [restorationFailure, ...closeErrors]
          : closeErrors,
        "Owned restoration file handles failed to close",
      );
    }
  }
}

function errorReceipt(error) {
  return {
    name: error instanceof Error ? error.name : "Error",
    message: error instanceof Error ? error.message : String(error),
    stack: error instanceof Error ? error.stack : undefined,
  };
}

export function finalizeQualificationOutcome({
  receipt,
  failure,
  ownedServersClosed,
  ownedProcessSettled,
}) {
  const hasProcessLaunchReceipt =
    receipt.process !== null
    && typeof receipt.process === "object"
    && Object.hasOwn(receipt.process, "pid");
  const acceptedNonNativeResult =
    !hasProcessLaunchReceipt
    && (receipt.result === "source-pass" || receipt.result === "unsupported");
  const finalizationErrors = [];
  if (!ownedServersClosed) {
    finalizationErrors.push(
      new Error("One or more owned loopback servers failed to close"),
    );
  }
  if (!ownedProcessSettled) {
    finalizationErrors.push(
      new Error("The launched owned VS Code process did not reach a settled exit"),
    );
  }
  let finalFailure = failure;
  if (!finalFailure && finalizationErrors.length === 1) {
    [finalFailure] = finalizationErrors;
  } else if (!finalFailure && finalizationErrors.length > 1) {
    finalFailure = new AggregateError(
      finalizationErrors,
      "Native qualification cleanup did not complete",
    );
  }
  if (
    !finalFailure
    && receipt.result !== "pass"
    && !acceptedNonNativeResult
  ) {
    finalFailure = new Error(
      `Native qualification ended with result ${String(receipt.result)}`,
    );
  }
  if (finalizationErrors.length > 0) {
    receipt.finalizationErrors = finalizationErrors.map(errorReceipt);
  }
  if (finalFailure) {
    receipt.result = "fail";
    if (receipt.coverage?.nativeCore?.result === "pass") {
      receipt.coverage.nativeCore.result = "fail";
    }
    receipt.error ??= errorReceipt(finalFailure);
  }
  return finalFailure;
}

export async function writeFinalQualificationReceipt({
  receiptPath,
  receipt,
  failure,
  ownedServersClosed,
  ownedProcessSettled,
}) {
  const finalFailure = finalizeQualificationOutcome({
    receipt,
    failure,
    ownedServersClosed,
    ownedProcessSettled,
  });
  await writeJson(receiptPath, receipt);
  if (finalFailure) throw finalFailure;
  return receipt;
}

async function pathExists(filePath) {
  return await access(filePath).then(() => true).catch((error) => {
    if (error?.code === "ENOENT") return false;
    throw error;
  });
}

export function buildNativeLaunchArgs({
  workspaceFile,
  userData,
  extensions,
  proxyUrl,
}) {
  return [
    workspaceFile,
    "--new-window",
    "--skip-welcome",
    "--skip-release-notes",
    "--disable-updates",
    "--disable-telemetry",
    "--use-inmemory-secretstorage",
    `--user-data-dir=${userData}`,
    `--extensions-dir=${extensions}`,
    `--extensionDevelopmentPath=${QA_EXTENSION}`,
    `--extensionTestsPath=${path.join(QA_EXTENSION, "suite.cjs")}`,
    `--proxy-server=${proxyUrl}`,
    "--verbose",
  ];
}

export function buildNativeProfileSettings({
  candidate,
  proxyUrl,
  sessionRoute,
}) {
  const settings = {
    "update.mode": "none",
    "extensions.autoUpdate": "off",
    "extensions.autoCheckUpdates": false,
    "telemetry.telemetryLevel": "off",
    "chat.allowAnonymousAccess": true,
    "chat.plugins.enabled": true,
    "chat.pluginLocations": {
      [candidate]: true,
    },
    "http.proxy": proxyUrl,
    "http.proxySupport": "override",
    "workbench.startupEditor": "none",
  };
  if (sessionRoute === "shared-copilot") {
    settings[SHARED_TITLE_SETTING] = "activeAgent";
  } else {
    assert.equal(sessionRoute, "legacy-local");
  }
  return settings;
}

export async function qualifyNativeVSCode(env = process.env) {
  const app = env.VSCODE_APP;
  const privateRoot = env.VSCODE_NATIVE_PRIVATE_ROOT;
  const receiptPath = env.NATIVE_QUALIFICATION_RECEIPT;
  assert.ok(app && path.isAbsolute(app), "VSCODE_APP must be absolute");
  const policy = resolvePortableQaPolicy(env);
  const layout = await createFreshQaLayout({
    privateRoot,
    receiptPath,
    policy,
  });
  const {
    trust: pendingTrustPath,
    disableAi: pendingAgentEnablePath,
    workspaceAi: pendingWorkspaceEnablePath,
    sharedModel: pendingSharedModelPath,
  } = policy.handoffs;
  const evidence = layout.evidence;
  const capturePath = path.join(evidence, "provider-capture.json");
  const providerJournalPath = path.join(
    evidence,
    "provider-tool-journal.ndjson",
  );
  const extensionInventoryPath = path.join(
    evidence,
    "extension-inventory.json",
  );
  const extensionInventoryAfterEnablePath = path.join(
    evidence,
    "extension-inventory-after-agent-enable.json",
  );
  const receipt = {
    schemaVersion: 1,
    qualification: "vscode-native-built-in-agent-hooks",
    resultScope: "source-preflight",
    result: "fail",
    coverage: createQualificationCoverage(),
    app: {},
    source: {},
    isolation: {},
    candidate: {},
    profile: {},
    process: {},
    outboundDestinations: [],
    classifierRequests: [],
    providerCapture: {},
    providerJournal: {
      path: providerJournalPath,
      result: "not-launched",
    },
    extensionInventory: {},
    agentEnablement: {
      policy,
    },
    evidence: [],
    freshProfile: {
      mode: policy.mode,
      outputRoot: layout.root,
      configurationRestored: false,
    },
    unsupported: {
      batchResume:
        "Unsupported: neither exact build exposes a public version-matched native queue/resume interface; previousRequests is history injection, not resume.",
    },
  };

  let classifier;
  let proxy;
  let failure;
  let freshRestore;
  let nativeLaunchAttempted = false;
  try {
    const preflightHome = path.join(layout.root, "preflight-home");
    await mkdir(preflightHome, { recursive: true, mode: 0o700 });
    const resolvedApp = await realpath(app);
    const appInfo = await lstat(resolvedApp);
    assert.ok(appInfo.isDirectory() && !appInfo.isSymbolicLink());
    const identity = await verifyApp(resolvedApp, preflightHome);
    receipt.app = {
      ...identity,
      path: resolvedApp,
      bundleDigest: await hashTree(resolvedApp),
    };
    receipt.source = await sourceReceipt(resolvedApp, identity);
    receipt.source.qaToolManifest = validateQaToolManifest(JSON.parse(
      await readFile(path.join(QA_EXTENSION, "package.json"), "utf8"),
    ));
    const nativeCjsMissingIdentifiers =
      inspectNativeCjsMissingIdentifiers();
    assert.deepEqual(
      nativeCjsMissingIdentifiers,
      [],
      `Refusing native launch; native CJS missing identifiers: ${JSON.stringify(nativeCjsMissingIdentifiers)}`,
    );
    receipt.source.nativeCjsPreflight = {
      result: "pass",
      checker: "typescript-allowJs-checkJs",
      files: nativeCjsFiles().map((filePath) =>
        path.relative(QA_EXTENSION, filePath)),
      missingIdentifierDiagnosticCodes: [
        ...MISSING_IDENTIFIER_DIAGNOSTIC_CODES,
      ],
    };
    receipt.isolation = {
      mode: "required-ephemeral-in-memory-secret-storage",
      flag: "--use-inmemory-secretstorage",
      sourceContracts: receipt.source.secretStorageIsolation,
      sourceHashes: {
        main: receipt.source.hashes.main,
        shared: receipt.source.hashes.shared,
        workbench: receipt.source.hashes.workbench,
        extensionHost: receipt.source.hashes.extensionHost,
        githubAuth: receipt.source.hashes.githubAuth,
      },
      runtimeSelection: "not-launched",
    };

    const requiredContracts = [
      "stableLanguageModelProvider",
      "scenarioAutomation",
      "chatOpenDriver",
      "pluginLocations",
      "transformedHook",
      "preToolHook",
      "postToolHook",
    ];
    const missing = requiredContracts.filter(
      (name) => receipt.source.contracts[name] !== true,
    );
    if (missing.length > 0) {
      receipt.result = "unsupported";
      receipt.unsupported.source = {
        version: identity.version,
        missing,
        launched: false,
        reason:
          "Exact-version source lacks the transformed native hook contract; minimum-version compatibility cannot be inferred.",
      };
      assert.equal(policy.allowLaunch, false,
        `Refusing native launch; missing exact source contracts: ${missing.join(", ")}`);
      return receipt;
    }
    const missingIsolation = Object.entries(
      receipt.source.secretStorageIsolation,
    ).filter(([, present]) => present !== true).map(([name]) => name);
    assert.deepEqual(
      missingIsolation,
      [],
      `Refusing native launch; missing secret-storage isolation contracts: ${missingIsolation.join(", ")}`,
    );
    const missingUiEnablement = Object.entries(
      receipt.source.normalUiAgentEnablement.contracts,
    ).filter(([, present]) => present !== true).map(([name]) => name);
    assert.deepEqual(
      missingUiEnablement,
      [],
      `Refusing portable QA; missing exact normal-UI source contracts: ${missingUiEnablement.join(", ")}`,
    );
    assert.equal(
      receipt.source.normalUiAgentEnablement.source.nlsMessagesSha256,
      NLS_MESSAGES_SHA256,
      "Signed app normal-UI labels changed from reviewed 1.145.2 source",
    );
    assert.equal(
      receipt.source.normalUiAgentEnablement.source.workbenchSha256,
      UI_WORKBENCH_SHA256,
      "Signed app normal-UI action source changed from reviewed 1.145.2 source",
    );
    assert.equal(
      receipt.source.hashes.copilotManifest,
      COPILOT_MANIFEST_SHA256,
      "Signed built-in Copilot manifest changed from reviewed 1.145.2 source",
    );
    assert.equal(
      receipt.source.hashes.copilot,
      COPILOT_SOURCE_SHA256,
      "Signed built-in Copilot implementation changed from reviewed 1.145.2 source",
    );
    if (policy.sessionRoute === "shared-copilot") {
      for (const [name, expected] of Object.entries(
        SHARED_ROUTE_SOURCE_SHA256,
      )) {
        assert.equal(
          receipt.source.hashes[name],
          expected,
          `Signed ${name} source changed from the coordinator-supplied PE capture`,
        );
      }
      const missingSharedContracts = Object.entries(
        receipt.source.sharedRouteContracts,
      ).filter(([, present]) => present !== true).map(([name]) => name);
      assert.deepEqual(
        missingSharedContracts,
        [],
        `Refusing shared-route QA; missing exact signed source contracts: ${missingSharedContracts.join(", ")}`,
      );
      assert.equal(
        receipt.source.sharedRouteReviewedOffsets.every(
          (entry) => entry.exact === true,
        ),
        true,
        "Signed shared-route source prefix moved from the coordinator-supplied PE byte offsets",
      );
      receipt.source.sharedRouteExperiment = {
        result: "source-admitted-runtime-unverified",
        sessionType: SHARED_SESSION_TYPE,
        titleGeneration: {
          key: SHARED_TITLE_SETTING,
          configuredValue: "activeAgent",
          stableDefault: "utility",
          scope: "application",
          appliesTo: "new shared sessions only",
        },
        sourceHashes: Object.fromEntries(
          Object.keys(SHARED_ROUTE_SOURCE_SHA256).map((name) => [
            name,
            receipt.source.hashes[name],
          ]),
        ),
        reviewedOffsets: receipt.source.sharedRouteReviewedOffsets,
        sessionSelectionSource: {
          targetChatSessionTypeHandling: "telemetry-only",
          wrappedModelVisibility:
            "filtered from Local picker; visible only for an existing matching non-Local session",
          visibleNewChat:
            "forwards the current session type through EEt/qDe",
          runtimeQualification:
            "requires first-safe-turn and final callback/log proof",
        },
        byokRegisteredProviderPath: {
          result: "source-admitted-runtime-unverified",
          providerType: "openai",
          wireApi: "responses",
          transport: "host-owned-127.0.0.1-loopback",
          rendererBridgeRequired: true,
          scope:
            "Intended deterministic registered-provider route only; not execution evidence.",
        },
        networkBoundary:
          "The application proxy records and allowlists observed proxy traffic; it is not OS-level network isolation.",
      };
    }

    const {
      home,
      userData,
      extensions,
      workspace,
      temporary,
      candidate,
    } = layout;
    for (const directory of [
      home,
      userData,
      extensions,
      workspace,
      temporary,
      evidence,
    ]) {
      await mkdir(directory, { recursive: true, mode: 0o700 });
      await chmod(directory, 0o700);
    }
    receipt.candidate = await copyCandidate(candidate);
    if (env.VSCODE_CANDIDATE_ARCHIVE) {
      assert.ok(path.isAbsolute(env.VSCODE_CANDIDATE_ARCHIVE));
      receipt.candidate.archive = {
        path: env.VSCODE_CANDIDATE_ARCHIVE,
        sha256: await sha256File(env.VSCODE_CANDIDATE_ARCHIVE),
      };
    }
    if (!policy.allowLaunch) {
      receipt.result = "source-pass";
      return receipt;
    }
    receipt.resultScope = policy.sessionRoute === "shared-copilot"
      ? "shared-copilot-four-case-native-core"
      : "four-case-native-core";
    receipt.coverage.nativeCore.result = "fail";

    classifier = startClassifier();
    proxy = startDestinationProxy();
    const [classifierUrl, proxyUrl] = await Promise.all([
      classifier.open(),
      proxy.open(),
    ]);

    const syntheticDeviceId = randomUUID();
    const syntheticMachineId = sha256Bytes(`SYNTHETIC:${randomUUID()}`);
    const syntheticSqmId = `{${randomUUID().toUpperCase()}}`;
    const globalStorage = path.join(userData, "User", "globalStorage");
    await mkdir(globalStorage, { recursive: true, mode: 0o700 });
    await writeJson(path.join(globalStorage, "storage.json"), {
      "telemetry.machineId": syntheticMachineId,
      "telemetry.sqmId": syntheticSqmId,
      "telemetry.devDeviceId": syntheticDeviceId,
      "telemetry.firstSessionDate": new Date().toUTCString(),
    });

    const settingsDirectory = path.join(userData, "User");
    const settingsPath = path.join(settingsDirectory, "settings.json");
    const configPath = path.join(home, ".vscode", "silmaril-firewall.json");
    await mkdir(settingsDirectory, { recursive: true, mode: 0o700 });
    await writeJson(settingsPath, buildNativeProfileSettings({
      candidate,
      proxyUrl,
      sessionRoute: policy.sessionRoute,
    }));
    const nodePath = await realpath(process.execPath);
    const nodeInfo = await stat(nodePath);
    assert.ok(nodeInfo.isFile());
    await mkdir(path.join(home, ".vscode"), { recursive: true, mode: 0o700 });
    await writeFile(
      path.join(home, ".vscode", "silmaril-firewall-node-path"),
      `${nodePath}\n`,
      { mode: 0o600 },
    );
    await writeJson(configPath, {
      schemaVersion: 1,
      enabled: true,
      apiKey: "SYNTHETIC_NATIVE_QA_ONLY",
      apiUrl: classifierUrl,
      mode: "block",
      timeoutMs: 2500,
      debug: true,
    });
    const windowTitle =
      `Silmaril Native QA ${identity.version} - Normal Workspace Trust Required`;
    const workspaceFile = layout.workspaceFile;
    await writeJson(workspaceFile, {
      folders: [{ path: workspace }],
      settings: {
        "window.title": windowTitle,
      },
    });
    const [settingsBytes, configBytes, workspaceFileBytes] = await Promise.all([
      readFile(settingsPath),
      readFile(configPath),
      readFile(workspaceFile),
    ]);
    freshRestore = {
      settingsPath,
      settingsBytes,
      activeSettingsBytes: settingsBytes,
      configPath,
      configBytes,
      activeConfigBytes: configBytes,
      workspaceFilePath: workspaceFile,
      workspaceFileBytes,
      archiveDirectory: path.join(evidence, "pre-restoration-files"),
    };
    receipt.freshProfile.configuration = {
      settingsBaselineSha256: sha256Bytes(settingsBytes),
      configBaselineSha256: sha256Bytes(configBytes),
      workspaceBaselineSha256: sha256Bytes(workspaceFileBytes),
    };
    const signedCopilotPath = await realpath(path.join(
      resolvedApp,
      "Contents",
      "Resources",
      "app",
      "extensions",
      "copilot",
    ));
    const signedCopilotInfo = await lstat(signedCopilotPath);
    assert.ok(
      signedCopilotInfo.isDirectory() && !signedCopilotInfo.isSymbolicLink(),
      "Signed Copilot source must be a regular application directory",
    );
    receipt.agentEnablement.expectedExtension = {
      id: receipt.source.copilot.id,
      version: receipt.source.copilot.version,
      path: signedCopilotPath,
      relativePath: "Contents/Resources/app/extensions/copilot",
      manifestSha256: receipt.source.hashes.copilotManifest,
      sourceSha256: receipt.source.hashes.copilot,
      isBuiltin: true,
    };
    receipt.agentEnablement.normalUiSource =
      receipt.source.normalUiAgentEnablement;
    const isolationReceiptPath = path.join(
      evidence,
      "secret-storage-isolation.json",
    );
    const preMarkerPath = path.join(workspace, "PRE_TOOL_SIDE_EFFECT_MARKER");
    const trustReadyPath = path.join(evidence, "normal-trust-ready.json");
    const aiDisableReadyPath = path.join(
      evidence,
      "normal-ui-disable-ai-ready.json",
    );
    const workspaceAiEnableReadyPath = path.join(
      evidence,
      "normal-ui-workspace-ai-enable-ready.json",
    );
    const sharedModelReadyPath = path.join(
      evidence,
      "normal-ui-shared-model-ready.json",
    );
    const profileResolvedPath = layout.root;
    const workspaceResolvedPath = await realpath(workspace);
    const existingLogDirectories = await listLogDirectoryNames(userData);
    receipt.profile = {
      syntheticDeviceId,
      syntheticMachineIdSha256: sha256Bytes(syntheticMachineId),
      home,
      userData,
      extensions,
      workspace,
      temporary,
      candidate,
      profileResolvedPath,
      workspaceResolvedPath,
      workspaceFile,
      outputRoot: layout.root,
      windowTitle,
      settingsSha256: await sha256File(settingsPath),
      configSha256: await sha256File(configPath),
      existingLogDirectories,
      classifierDestination: classifierUrl,
      proxyDestination: proxyUrl,
    };

    const removedEnvironmentNames = Object.keys(env).filter(
      (name) => FORBIDDEN_AUTH_ENV.includes(name),
    );
    const childEnv = buildMinimalChildEnvironment(env, {
      HOME: home,
      TMPDIR: temporary,
      XDG_CACHE_HOME: path.join(layout.root, "xdg-cache"),
      XDG_CONFIG_HOME: path.join(layout.root, "xdg-config"),
      XDG_DATA_HOME: path.join(layout.root, "xdg-data"),
      IS_SCENARIO_AUTOMATION: "1",
      SILMARIL_CONFIG_PATH: configPath,
      SILMARIL_LOCAL_EVENT_DIR: evidence,
      SILMARIL_VSCODE_WORKSPACE_STATE: path.join(evidence, "observed-workspaces.json"),
      SILMARIL_NATIVE_CAPTURE_PATH: capturePath,
      SILMARIL_NATIVE_PROVIDER_JOURNAL_PATH: providerJournalPath,
      SILMARIL_NATIVE_EXTENSION_INVENTORY_PATH: extensionInventoryPath,
      SILMARIL_NATIVE_EXTENSION_INVENTORY_AFTER_ENABLE_PATH:
        extensionInventoryAfterEnablePath,
      SILMARIL_NATIVE_ISOLATION_RECEIPT_PATH: isolationReceiptPath,
      SILMARIL_NATIVE_PRE_MARKER_PATH: preMarkerPath,
      SILMARIL_NATIVE_TRUST_READY_PATH: trustReadyPath,
      SILMARIL_NATIVE_AI_DISABLE_READY_PATH: aiDisableReadyPath,
      SILMARIL_NATIVE_AI_WORKSPACE_ENABLE_READY_PATH:
        workspaceAiEnableReadyPath,
      ...(policy.sessionRoute === "shared-copilot"
        ? {
            SILMARIL_NATIVE_SHARED_MODEL_READY_PATH: sharedModelReadyPath,
            SILMARIL_NATIVE_SHARED_MODEL_PENDING_PATH:
              pendingSharedModelPath,
            SILMARIL_NATIVE_SESSION_ROUTE: policy.sessionRoute,
          }
        : {}),
      SILMARIL_NATIVE_PROFILE_SETTINGS_PATH: settingsPath,
      SILMARIL_NATIVE_WORKSPACE_FILE_PATH: workspaceFile,
      SILMARIL_NATIVE_USER_DATA: userData,
      SILMARIL_NATIVE_SYNTHETIC_DEVICE_ID: syntheticDeviceId,
      SILMARIL_NATIVE_WINDOW_TITLE: windowTitle,
      SILMARIL_NATIVE_EXPECTED_COPILOT_PATH: signedCopilotPath,
      SILMARIL_NATIVE_EXPECTED_COPILOT_VERSION:
        receipt.source.copilot.version,
      SILMARIL_NATIVE_EXPECTED_COPILOT_MANIFEST_SHA256:
        receipt.source.hashes.copilotManifest,
      SILMARIL_NATIVE_EXPECTED_COPILOT_SOURCE_SHA256:
        receipt.source.hashes.copilot,
      SILMARIL_NATIVE_EXISTING_LOG_DIRECTORIES:
        JSON.stringify(existingLogDirectories),
      SILMARIL_NATIVE_ALLOW_NORMAL_TRUST_HANDOFF:
        policy.allowNormalTrustHandoff ? "1" : "0",
      SILMARIL_NATIVE_ALLOW_UI_ENABLE_HANDOFF:
        policy.allowUiEnableHandoff ? "1" : "0",
      HTTPS_PROXY: proxyUrl,
      HTTP_PROXY: proxyUrl,
      ALL_PROXY: proxyUrl,
      NO_PROXY: "127.0.0.1,localhost",
      no_proxy: "127.0.0.1,localhost",
      ELECTRON_ENABLE_LOGGING: "1",
    });
    receipt.profile.environment = {
      strategy: "minimal-allowlist",
      childNames: Object.keys(childEnv).sort(),
      omittedKnownCredentialNames: removedEnvironmentNames.sort(),
      callerEnvironmentValuesRecorded: false,
    };

    const executable = path.join(resolvedApp, "Contents", "MacOS", "Code");
    const stdoutPath = path.join(evidence, "vscode-stdout.log");
    const stderrPath = path.join(evidence, "vscode-stderr.log");
    const launchArgs = buildNativeLaunchArgs({
      workspaceFile,
      userData,
      extensions,
      proxyUrl,
    });
    assert.ok(launchArgs.includes("--use-inmemory-secretstorage"));
    assert.equal(
      launchArgs.some((argument) => argument.startsWith("--password-store")),
      false,
      "Native QA must not select a plaintext password store",
    );
    const handoffs = [];
    if (pendingTrustPath) {
      handoffs.push({
        readyPath: trustReadyPath,
        pendingPath: pendingTrustPath,
        pendingState: "waiting-for-normal-workspace-trust",
        readyTimeoutMs: TRUST_READY_TIMEOUT_MS,
        readinessDescription: "the normal-trust prompt",
        pendingContext: {
          appPath: resolvedApp,
          appVersion: identity.version,
          appCommit: identity.commit,
          profileResolvedPath,
          workspaceResolvedPath,
          workspaceFile: await realpath(workspaceFile),
          windowTitle,
          receiptPath,
        },
      });
    }
    if (pendingAgentEnablePath) {
      handoffs.push({
        readyPath: aiDisableReadyPath,
        pendingPath: pendingAgentEnablePath,
        pendingState: "waiting-for-normal-ui-disable-ai",
        readyTimeoutMs: AI_DISABLE_READY_TIMEOUT_MS,
        readinessDescription: "the normal-UI Disable AI Features handoff",
        pendingContext: {
          appPath: resolvedApp,
          appVersion: identity.version,
          appCommit: identity.commit,
          profileResolvedPath,
          workspaceResolvedPath,
          workspaceFile: await realpath(workspaceFile),
          windowTitle,
          receiptPath,
          sourceProof: receipt.agentEnablement,
          normalUiInstruction: {
            surface: "Extensions view",
            extensionId: "github.copilot-chat",
            phase: 1,
            actionIdFromSignedSource: "extensions.disableAIGlobally",
            actionLabel: "Disable AI Features",
            forbiddenActions: [
              "install",
              "sign-in",
              "account setup",
              "chat setup",
            ],
          },
        },
      });
    }
    if (pendingWorkspaceEnablePath) {
      handoffs.push({
        readyPath: workspaceAiEnableReadyPath,
        pendingPath: pendingWorkspaceEnablePath,
        pendingState: "waiting-for-normal-ui-workspace-ai-enable",
        readyTimeoutMs: WORKSPACE_AI_ENABLE_READY_TIMEOUT_MS,
        readinessDescription:
          "the normal-UI Enable AI Features (Workspace) handoff",
        pendingContext: {
          appPath: resolvedApp,
          appVersion: identity.version,
          appCommit: identity.commit,
          profileResolvedPath,
          workspaceResolvedPath,
          workspaceFile: await realpath(workspaceFile),
          windowTitle,
          receiptPath,
          sourceProof: receipt.agentEnablement,
          normalUiInstruction: {
            surface: "Extensions view",
            extensionId: "github.copilot-chat",
            phase: 2,
            actionIdFromSignedSource: "extensions.enableAIInWorkspace",
            actionLabel: "Enable AI Features (Workspace)",
            forbiddenActions: [
              "install",
              "sign-in",
              "account setup",
              "chat setup",
            ],
          },
        },
      });
    }
    if (pendingSharedModelPath) {
      handoffs.push({
        readyPath: sharedModelReadyPath,
        pendingPath: pendingSharedModelPath,
        pendingState:
          "waiting-for-normal-visible-shared-session-and-model-selection",
        readyTimeoutMs: WORKSPACE_AI_ENABLE_READY_TIMEOUT_MS,
        readinessDescription:
          "the normal visible shared session/harness and wrapped-model picker handoff",
        pendingContext: {
          appPath: resolvedApp,
          appVersion: identity.version,
          appCommit: identity.commit,
          profileResolvedPath,
          workspaceResolvedPath,
          workspaceFile: await realpath(workspaceFile),
          windowTitle,
          receiptPath,
          sourceProof: receipt.source.sharedRouteExperiment,
          normalUiInstruction: {
            actionsInOrder: [
              {
                surface: "Chat session/harness picker",
                action:
                  "Select the advertised shared Copilot session/harness and observe target session type agent-host-copilotcli in the normal visible UI or fresh-profile host log.",
              },
              {
                surface: "Chat model picker",
                action:
                  "Select the host-published Silmaril Native QA Local Deterministic Dummy entry whose ready.publicModel has vendor agent-host-copilotcli and the exact observed id.",
              },
            ],
            forbiddenActions: [
              "synthetic command selection",
              "sign-in",
              "account setup",
              "provider setup",
              "real inference",
            ],
            completion:
              "If either entry is absent or requires authentication/provider setup, stop unverified. After both visible selections, replace this contained marker with the documented human-ui-selection-action-only attestation. These attest only the UI actions; model selection does not create the route and runtime proof remains mandatory.",
          },
        },
      });
    }
    nativeLaunchAttempted = true;
    receipt.process = await launchApp({
      executable,
      args: launchArgs,
      cwd: workspace,
      env: childEnv,
      stdoutPath,
      stderrPath,
      capturePath,
      handoffs,
      processTimeoutMs: policy.allowUiEnableHandoff
        ? UI_HANDOFF_PROCESS_TIMEOUT_MS
        : PROCESS_TIMEOUT_MS,
    });
    assert.equal(
      receipt.process.parentSignal,
      undefined,
      `Native qualification interrupted by ${receipt.process.parentSignal}; exact owned process group was stopped`,
    );
    receipt.process.executable = executable;
    receipt.process.arguments = launchArgs;
    receipt.process.stdout = {
      path: stdoutPath,
      sha256: await sha256File(stdoutPath),
    };
    receipt.process.stderr = {
      path: stderrPath,
      sha256: await sha256File(stderrPath),
    };
    const postLaunchLogDirectories = await listLogDirectoryNames(userData);
    receipt.profile.currentLaunchLogDirectories =
      postLaunchLogDirectories.filter(
        (entry) => !existingLogDirectories.includes(entry),
      );
    assert.ok(
      receipt.profile.currentLaunchLogDirectories.length > 0,
      "No fresh VS Code log directory was created for this invocation",
    );
    const runtimeLogs = await readCurrentLaunchLogEvidence(
      userData,
      receipt.profile.currentLaunchLogDirectories,
    );
    receipt.profile.currentLaunchLogs = runtimeLogs.files;
    assert.equal(
      await pathExists(isolationReceiptPath),
      true,
      "In-memory secret-storage runtime selection was not confirmed; native QA stopped",
    );
    receipt.isolation.runtimeSelection = {
      path: isolationReceiptPath,
      sha256: await sha256File(isolationReceiptPath),
      ...JSON.parse(await readFile(isolationReceiptPath, "utf8")),
    };
    assert.equal(
      receipt.isolation.runtimeSelection.result,
      "pass",
      receipt.isolation.runtimeSelection.error?.message
        ?? "In-memory secret-storage runtime selection failed",
    );
    assert.equal(receipt.process.timedOut, false, "VS Code extension test timed out");
    assert.equal(
      receipt.process.code,
      0,
      `VS Code extension test exited ${receipt.process.code ?? receipt.process.signal}`,
    );

    const capture = JSON.parse(await readFile(capturePath, "utf8"));
    receipt.providerCapture = {
      path: capturePath,
      sha256: await sha256File(capturePath),
      ...capture,
    };
    receipt.classifierRequests = classifier.requests;
    const preMarkerExists = await pathExists(preMarkerPath);
    validateNativeEvidence(
      capture,
      classifier.requests,
      preMarkerExists,
      receipt.coverage,
      policy.sessionRoute,
      runtimeLogs.combinedLogs,
    );
    receipt.evidence = await listEvidence(evidence);

    const actualDestinations = proxy.destinations.map((entry) => entry.destination);
    assert.ok(
      actualDestinations.includes("api.github.com:443"),
      "Anonymous no-auth control-plane destination was not observed through the QA proxy",
    );
    assert.equal(
      actualDestinations.some((destination) =>
        FORBIDDEN_MODEL_DESTINATIONS.some((host) => destination.startsWith(host))),
      false,
      "A real model/provider destination was requested",
    );
    receipt.coverage.nativeCore.result = "pass";
    receipt.result = "pass";
  } catch (error) {
    failure = error;
    if (
      error
      && typeof error === "object"
      && error.processReceipt
      && typeof error.processReceipt === "object"
    ) {
      receipt.process = error.processReceipt;
    }
    receipt.error = {
      name: error instanceof Error ? error.name : "Error",
      message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    };
  } finally {
    if (classifier) receipt.classifierRequests = classifier.requests;
    if (proxy) receipt.outboundDestinations = proxy.destinations;
    if (await pathExists(capturePath) && !receipt.providerCapture.path) {
      try {
        receipt.providerCapture = {
          path: capturePath,
          sha256: await sha256File(capturePath),
          ...JSON.parse(await readFile(capturePath, "utf8")),
        };
      } catch (captureError) {
        receipt.providerCapture = {
          path: capturePath,
          error:
            captureError instanceof Error
              ? captureError.message
              : String(captureError),
        };
      }
    }
    if (await pathExists(extensionInventoryPath)) {
      try {
        const extensionInventory = JSON.parse(
          await readFile(extensionInventoryPath, "utf8"),
        );
        receipt.extensionInventory = {
          path: extensionInventoryPath,
          sha256: await sha256File(extensionInventoryPath),
          count: extensionInventory.count,
          copilotChatMatches: extensionInventory.copilotChatMatches,
          source: extensionInventory.source,
          extensions: extensionInventory.extensions,
        };
      } catch (inventoryError) {
        receipt.extensionInventory = {
          path: extensionInventoryPath,
          error:
            inventoryError instanceof Error
              ? inventoryError.message
              : String(inventoryError),
        };
      }
    }
    if (await pathExists(extensionInventoryAfterEnablePath)) {
      try {
        const afterEnableInventory = JSON.parse(
          await readFile(extensionInventoryAfterEnablePath, "utf8"),
        );
        receipt.agentEnablement.afterEnableInventory = {
          path: extensionInventoryAfterEnablePath,
          sha256: await sha256File(extensionInventoryAfterEnablePath),
          ...afterEnableInventory,
        };
      } catch (inventoryError) {
        receipt.agentEnablement.afterEnableInventory = {
          path: extensionInventoryAfterEnablePath,
          error:
            inventoryError instanceof Error
              ? inventoryError.message
              : String(inventoryError),
        };
      }
    }
    const serverClosers = [
      ["classifier", classifier?.close.bind(classifier)],
      ["proxy", proxy?.close.bind(proxy)],
    ].filter(([, close]) => close);
    const closes = await Promise.allSettled(
      serverClosers.map(([, close]) => close()),
    );
    receipt.ownedServersClosed = closes.every(
      (outcome) => outcome.status === "fulfilled",
    );
    receipt.serverCleanup = {
      result: receipt.ownedServersClosed ? "pass" : "fail",
      servers: closes.map((outcome, index) => ({
        name: serverClosers[index][0],
        result: outcome.status,
        error: outcome.status === "rejected"
          ? errorReceipt(outcome.reason)
          : undefined,
      })),
    };
    if (!receipt.ownedServersClosed && !failure) {
      failure = new Error("One or more owned loopback servers failed to close");
      receipt.error ??= errorReceipt(failure);
    }

    const leaderSettled =
      !nativeLaunchAttempted
      || Number.isInteger(receipt.process.code)
      || typeof receipt.process.signal === "string";
    try {
      if (
        nativeLaunchAttempted
        && !Number.isSafeInteger(receipt.process.pid)
      ) {
        throw new Error(
          "Native launch was attempted without a captured owned process-group PID",
        );
      }
      receipt.processGroupCleanup = await settleOwnedProcessGroup(
        receipt.process,
      );
      receipt.processGroupCleanup.leaderSettled = leaderSettled;
    } catch (groupCleanupError) {
      receipt.processGroupCleanup = {
        ...(groupCleanupError
          && typeof groupCleanupError === "object"
          && groupCleanupError.processGroupCleanup
          ? groupCleanupError.processGroupCleanup
          : {}),
        result: "fail",
        groupAbsent: false,
        leaderSettled,
        error: errorReceipt(groupCleanupError),
      };
      if (!failure) {
        failure = groupCleanupError;
        receipt.error ??= errorReceipt(groupCleanupError);
      }
    }
    receipt.ownedProcessSettled =
      leaderSettled
      && receipt.processGroupCleanup.groupAbsent === true;

    if (nativeLaunchAttempted) {
      try {
        if (!await pathExists(providerJournalPath)) {
          throw new Error("Native provider/tool journal was not created");
        }
        receipt.providerJournal =
          await inspectProviderJournal(providerJournalPath);
        if (receipt.providerJournal.integrity !== "pass") {
          throw new Error(
            "Native provider/tool journal failed integrity validation",
          );
        }
        if (receipt.result === "pass") {
          receipt.providerJournal.finishedCaptureConsistency =
            validateProviderJournalCapture(
              receipt.providerJournal,
              receipt.providerCapture,
            );
        }
      } catch (journalError) {
        receipt.providerJournal = {
          ...receipt.providerJournal,
          path: providerJournalPath,
          result: "fail",
          error: errorReceipt(journalError),
        };
        if (!failure) {
          failure = journalError;
          receipt.error ??= errorReceipt(journalError);
        }
      }
    }

    if (freshRestore && receipt.ownedProcessSettled) {
      let inspectionError;
      let observed;
      let classification;
      const archives = {};
      try {
        await assertOwnedPathWithin(
          layout.root,
          freshRestore.settingsPath,
          "file",
        );
        await assertOwnedPathWithin(
          layout.root,
          freshRestore.configPath,
          "file",
        );
        await assertOwnedPathWithin(
          layout.root,
          freshRestore.workspaceFilePath,
          "file",
        );
        observed = {
          settings: await readFile(freshRestore.settingsPath),
          config: await readFile(freshRestore.configPath),
          workspace: await readFile(
            freshRestore.workspaceFilePath,
          ),
        };
        const observation = await inspectAndArchiveFreshUiFiles({
          activeSettingsBytes: freshRestore.activeSettingsBytes,
          activeConfigBytes: freshRestore.activeConfigBytes,
          originalWorkspaceBytes: freshRestore.workspaceFileBytes,
          observedSettingsBytes: observed.settings,
          observedConfigBytes: observed.config,
          observedWorkspaceBytes: observed.workspace,
          archiveDirectory: freshRestore.archiveDirectory,
        });
        classification = observation.classification;
        Object.assign(archives, observation.archives);
      } catch (error) {
        inspectionError = error;
      }
      try {
        const restoration = await restoreFreshProfileFiles({
          ownedProfileRoot: layout.root,
          settingsPath: freshRestore.settingsPath,
          settingsBytes: freshRestore.settingsBytes,
          configPath: freshRestore.configPath,
          configBytes: freshRestore.configBytes,
          workspaceFilePath: freshRestore.workspaceFilePath,
          workspaceFileBytes: freshRestore.workspaceFileBytes,
        });
        receipt.freshProfile.configurationRestored = true;
        receipt.freshProfile.uiFileObservation = {
          checkedAfterOwnedProcessExit: true,
          archives,
          classification,
          restoration,
        };
        if (inspectionError) throw inspectionError;
        assert.equal(
          classification.expected,
          true,
          "Normal UI made an unexpected synthetic settings, config, or workspace change; observed bytes were archived and originals restored",
        );
      } catch (restoreError) {
        receipt.freshProfile.configurationRestored =
          receipt.freshProfile.configurationRestored === true;
        receipt.freshProfile.restorationError = {
          name: restoreError instanceof Error ? restoreError.name : "Error",
          message:
            restoreError instanceof Error
              ? restoreError.message
              : String(restoreError),
        };
        if (!failure) {
          failure = restoreError;
          receipt.error = receipt.freshProfile.restorationError;
        }
      }
    } else if (freshRestore) {
      receipt.freshProfile.configurationRestored = false;
      receipt.freshProfile.uiFileObservation = {
        checkedAfterOwnedProcessExit: false,
        restorationSkipped:
          "Owned process-group absence was not proven; no restoration write was attempted",
      };
    }
    await writeFinalQualificationReceipt({
      receiptPath,
      receipt,
      failure,
      ownedServersClosed: receipt.ownedServersClosed,
      ownedProcessSettled: receipt.ownedProcessSettled,
    });
  }
  return receipt;
}

async function main() {
  const receipt = await qualifyNativeVSCode();
  process.stdout.write(`${JSON.stringify({
    result: receipt.result,
    version: receipt.app.version,
    commit: receipt.app.commit,
    contracts: receipt.source.contracts,
    providerRequests: receipt.providerCapture.providerRequests?.length ?? 0,
    classifierRequests: receipt.classifierRequests.length,
    outboundDestinations: receipt.outboundDestinations,
  })}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  await main();
}
