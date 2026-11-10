"use strict";

const path = require("node:path");

const MAX_EXTENSIONS = 10_000;
const MAX_FIELD_LENGTH = 256;

function boundedString(value, field) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Extension inventory ${field} must be a non-empty string`);
  }
  if (value.length > MAX_FIELD_LENGTH) {
    throw new Error(`Extension inventory ${field} exceeds ${MAX_FIELD_LENGTH} characters`);
  }
  return value;
}

function extensionKindName(value) {
  if (value === 1) return "ui";
  if (value === 2) return "workspace";
  return `unknown-${String(value)}`;
}

function safeExtensionLocation(extensionUri) {
  const scheme = boundedString(extensionUri?.scheme, "location scheme");
  const fsPath = extensionUri?.fsPath;
  const basename = boundedString(
    typeof fsPath === "string" && fsPath.length > 0
      ? path.basename(fsPath)
      : path.posix.basename(extensionUri?.path ?? ""),
    "location basename",
  );
  return { scheme, basename };
}

function buildSafeExtensionInventory(extensions) {
  if (!Array.isArray(extensions)) {
    throw new Error("Extension inventory input must be an array");
  }
  if (extensions.length > MAX_EXTENSIONS) {
    throw new Error(`Extension inventory exceeds ${MAX_EXTENSIONS} entries`);
  }
  const entries = extensions.map((extension) => ({
    id: boundedString(extension.id, "id").toLowerCase(),
    version: boundedString(extension.packageJSON?.version, "version"),
    extensionKind: extensionKindName(extension.extensionKind),
    isBuiltin: extension.packageJSON?.isBuiltin === true,
    isActive: extension.isActive === true,
    location: safeExtensionLocation(extension.extensionUri),
    runningLocation:
      "not-exposed-by-public-vscode-extension-api",
  }));
  entries.sort((left, right) => left.id.localeCompare(right.id));
  return entries;
}

module.exports = {
  MAX_EXTENSIONS,
  MAX_FIELD_LENGTH,
  buildSafeExtensionInventory,
};
