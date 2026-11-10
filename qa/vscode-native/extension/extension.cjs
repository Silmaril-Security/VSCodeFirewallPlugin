"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const vscode = require("vscode");
const { createProviderJournal } = require("./provider-journal.cjs");

const VENDOR = "silmaril-native-qa-dummy-8d724ae7";
const MODEL_ID = "silmaril-native-qa-local-deterministic-8d724ae7";
const PRE_TOOL = "silmaril_native_qa_preblock_8d724ae7";
const POST_TOOL = "silmaril_native_qa_posttool_8d724ae7";
const PRE_MARKER = "SILMARIL_NATIVE_PREBLOCK_8d724ae7";
const POST_MARKER = "SILMARIL_NATIVE_POSTTOOL_8d724ae7";
const POISON_MARKER = "SILMARIL_NATIVE_POISON_8d724ae7";

const state = {
  providerRequests: [],
  providerCallCount: 0,
  issuedToolCalls: new Set(),
  toolInvocations: {
    [PRE_TOOL]: 0,
    [POST_TOOL]: 0,
  },
};

function serializePart(part) {
  if (part instanceof vscode.LanguageModelTextPart) {
    return { type: "text", value: part.value };
  }
  if (part instanceof vscode.LanguageModelToolCallPart) {
    return {
      type: "toolCall",
      callId: part.callId,
      name: part.name,
      input: part.input,
    };
  }
  if (part instanceof vscode.LanguageModelToolResultPart) {
    return {
      type: "toolResult",
      callId: part.callId,
      content: part.content.map(serializePart),
    };
  }
  return {
    type: part?.constructor?.name ?? typeof part,
    value: typeof part?.value === "string" ? part.value : undefined,
  };
}

function serializeMessages(messages) {
  return messages.map((message) => ({
    role: message.role,
    name: message.name,
    content: message.content.map(serializePart),
  }));
}

function collectStrings(value, output = []) {
  if (typeof value === "string") {
    output.push(value);
  } else if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, output);
  } else if (value && typeof value === "object") {
    for (const item of Object.values(value)) collectStrings(item, output);
  }
  return output;
}

function toolForRequest(strings) {
  if (strings.some((value) => value.includes(PRE_MARKER))) return PRE_TOOL;
  if (strings.some((value) => value.includes(POST_MARKER))) return POST_TOOL;
  return undefined;
}

async function activate(context) {
  const journalPath = process.env.SILMARIL_NATIVE_PROVIDER_JOURNAL_PATH;
  assert.ok(
    journalPath && path.isAbsolute(journalPath),
    "Missing private provider journal path",
  );
  const journal = await createProviderJournal(journalPath);
  context.subscriptions.push({
    dispose() {
      void journal.close();
    },
  });
  const model = {
    id: MODEL_ID,
    name: "Silmaril Native QA Local Deterministic Dummy",
    family: "silmaril-native-qa-dummy",
    version: "1",
    maxInputTokens: 32_768,
    maxOutputTokens: 1_024,
    capabilities: {
      toolCalling: true,
      imageInput: false,
    },
  };

  context.subscriptions.push(vscode.lm.registerLanguageModelChatProvider(VENDOR, {
    provideLanguageModelChatInformation() {
      return [model];
    },
    async provideLanguageModelChatResponse(
      selectedModel,
      messages,
      options,
      progress,
    ) {
      if (selectedModel.id !== MODEL_ID) {
        throw new Error(`Unexpected model requested: ${selectedModel.id}`);
      }
      const serializedMessages = serializeMessages(messages);
      const strings = collectStrings(serializedMessages);
      const tool = toolForRequest(strings);
      state.providerCallCount += 1;
      const providerRequest = {
        sequence: state.providerCallCount,
        model: {
          id: selectedModel.id,
          family: selectedModel.family,
          version: selectedModel.version,
        },
        messages: serializedMessages,
        tools: (options.tools ?? []).map((entry) => entry.name),
        toolMode: options.toolMode,
      };
      state.providerRequests.push(providerRequest);
      await journal.append({
        type: "provider-request",
        providerSequence: state.providerCallCount,
        request: providerRequest,
      });

      if (tool && !state.issuedToolCalls.has(tool)) {
        if (!(options.tools ?? []).some((entry) => entry.name === tool)) {
          throw new Error(`Required synthetic tool was not offered: ${tool}`);
        }
        state.issuedToolCalls.add(tool);
        progress.report(new vscode.LanguageModelToolCallPart(
          `silmaril-native-call-${tool}`,
          tool,
          { marker: tool === PRE_TOOL ? PRE_MARKER : POST_MARKER },
        ));
        return;
      }

      progress.report(new vscode.LanguageModelTextPart(
        `SILMARIL_NATIVE_DUMMY_RESPONSE_${state.providerCallCount}`,
      ));
    },
    async provideTokenCount(_selectedModel, text) {
      const encoded = typeof text === "string" ? text : JSON.stringify(serializeMessages([text]));
      return Math.max(1, Math.ceil(Buffer.byteLength(encoded, "utf8") / 4));
    },
  }));

  context.subscriptions.push(vscode.lm.registerTool(PRE_TOOL, {
    async invoke() {
      state.toolInvocations[PRE_TOOL] += 1;
      await journal.append({
        type: "tool-invocation",
        toolName: PRE_TOOL,
        invocationCount: state.toolInvocations[PRE_TOOL],
      });
      const markerPath = process.env.SILMARIL_NATIVE_PRE_MARKER_PATH;
      if (!markerPath) throw new Error("Missing private pre-tool marker path");
      await fs.writeFile(markerPath, `${PRE_MARKER}\n`, { mode: 0o600 });
      return new vscode.LanguageModelToolResult([
        new vscode.LanguageModelTextPart("SILMARIL_NATIVE_PRE_TOOL_RAN"),
      ]);
    },
  }));

  context.subscriptions.push(vscode.lm.registerTool(POST_TOOL, {
    async invoke() {
      state.toolInvocations[POST_TOOL] += 1;
      await journal.append({
        type: "tool-invocation",
        toolName: POST_TOOL,
        invocationCount: state.toolInvocations[POST_TOOL],
      });
      return new vscode.LanguageModelToolResult([
        new vscode.LanguageModelTextPart(POISON_MARKER),
      ]);
    },
  }));

  return {
    state,
    constants: {
      VENDOR,
      MODEL_ID,
      PRE_TOOL,
      POST_TOOL,
      PRE_MARKER,
      POST_MARKER,
      POISON_MARKER,
    },
    collectStrings,
    journal,
  };
}

function deactivate() {}

module.exports = { activate, deactivate };
