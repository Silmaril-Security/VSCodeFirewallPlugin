"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");

const JOURNAL_SCHEMA_VERSION = 1;
const JOURNAL_STATE = "in-progress";
const JOURNAL_COMPLETION = "not-finished";
const JOURNAL_TYPES = new Set(["provider-request", "tool-invocation"]);

function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function createProviderJournal(filePath) {
  assert.ok(
    typeof filePath === "string" && path.isAbsolute(filePath),
    "Provider journal path must be absolute",
  );
  const handle = await fsp.open(
    filePath,
    fs.constants.O_WRONLY
      | fs.constants.O_CREAT
      | fs.constants.O_EXCL
      | fs.constants.O_NOFOLLOW,
    0o600,
  );
  try {
    const [pathInfo, handleInfo] = await Promise.all([
      fsp.lstat(filePath),
      handle.stat(),
    ]);
    assert.equal(pathInfo.isSymbolicLink(), false);
    assert.equal(pathInfo.isFile(), true);
    assert.equal(handleInfo.isFile(), true);
    assert.equal(pathInfo.dev, handleInfo.dev);
    assert.equal(pathInfo.ino, handleInfo.ino);
    assert.equal(pathInfo.mode & 0o777, 0o600);
    if (typeof process.getuid === "function") {
      assert.equal(pathInfo.uid, process.getuid());
      assert.equal(handleInfo.uid, process.getuid());
    }
  } catch (error) {
    await handle.close();
    throw error;
  }

  let nextSequence = 0;
  let queue = Promise.resolve();
  let closed = false;
  const append = async (record) => {
    assert.equal(closed, false, "Provider journal is closed");
    assert.ok(record && typeof record === "object");
    assert.equal(JOURNAL_TYPES.has(record.type), true);
    const journalRecord = {
      ...record,
      schemaVersion: JOURNAL_SCHEMA_VERSION,
      journalSequence: ++nextSequence,
      state: JOURNAL_STATE,
      completion: JOURNAL_COMPLETION,
    };
    const line = `${JSON.stringify(journalRecord)}\n`;
    queue = queue.then(async () => {
      await handle.writeFile(line, "utf8");
      await handle.sync();
    });
    await queue;
    return journalRecord;
  };
  return {
    append,
    async flush() {
      await queue;
      await handle.sync();
    },
    async close() {
      if (closed) return;
      closed = true;
      try {
        await queue;
        await handle.sync();
      } finally {
        await handle.close();
      }
    },
  };
}

function validateRecord(record, expectedSequence) {
  assert.ok(record && typeof record === "object");
  assert.equal(record.schemaVersion, JOURNAL_SCHEMA_VERSION);
  assert.equal(record.journalSequence, expectedSequence);
  assert.equal(record.state, JOURNAL_STATE);
  assert.equal(record.completion, JOURNAL_COMPLETION);
  assert.equal(JOURNAL_TYPES.has(record.type), true);
  if (record.type === "provider-request") {
    assert.ok(Number.isSafeInteger(record.providerSequence));
    assert.ok(record.providerSequence > 0);
    assert.ok(record.request && typeof record.request === "object");
  } else {
    assert.equal(typeof record.toolName, "string");
    assert.ok(record.toolName.length > 0);
    assert.ok(Number.isSafeInteger(record.invocationCount));
    assert.ok(record.invocationCount > 0);
  }
}

function parseProviderJournalBytes(value) {
  const bytes = Buffer.from(value);
  const lastNewline = bytes.lastIndexOf(0x0a);
  const completeBytes = bytes.subarray(0, lastNewline + 1);
  const trailing = bytes.subarray(lastNewline + 1);
  const lines = completeBytes.toString("latin1").split("\n");
  lines.pop();
  const records = [];
  const errors = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line) {
      errors.push({
        line: index + 1,
        message: "Provider journal contains an empty complete line",
      });
      continue;
    }
    try {
      const decoded = new TextDecoder("utf-8", { fatal: true }).decode(
        Buffer.from(line, "latin1"),
      );
      const record = JSON.parse(decoded);
      validateRecord(record, index + 1);
      records.push(record);
    } catch (error) {
      errors.push({
        line: index + 1,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }
  const partialTrailingLine = trailing.length > 0
    ? {
        byteLength: trailing.byteLength,
        sha256: sha256Bytes(trailing),
        base64: trailing.toString("base64"),
      }
    : undefined;
  return {
    integrity: errors.length === 0 && !partialTrailingLine ? "pass" : "fail",
    validRecordCount: records.length,
    records,
    errors,
    partialTrailingLine,
  };
}

module.exports = {
  createProviderJournal,
  parseProviderJournalBytes,
};
