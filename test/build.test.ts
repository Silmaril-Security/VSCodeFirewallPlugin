import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFile, cp, mkdir, mkdtemp, readFile, rm, symlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

test("build resolves a checkout path containing spaces and non-ASCII characters", async () => {
  const repo = fileURLToPath(new URL("../", import.meta.url));
  const checkout = await mkdtemp(path.join(os.tmpdir(), "vscode checkout café-"));
  try {
    await mkdir(path.join(checkout, "scripts"));
    await copyFile(path.join(repo, "scripts/build.mjs"), path.join(checkout, "scripts/build.mjs"));
    await copyFile(path.join(repo, "package.json"), path.join(checkout, "package.json"));
    await cp(path.join(repo, "src"), path.join(checkout, "src"), { recursive: true });
    await symlink(path.join(repo, "node_modules"), path.join(checkout, "node_modules"), "junction");

    execFileSync(process.execPath, [path.join(checkout, "scripts/build.mjs")], { cwd: checkout });

    const bundle = await readFile(path.join(checkout, "dist/vscode-hook.js"), "utf8");
    assert.ok(bundle.length > 0);
  } finally {
    await rm(checkout, { recursive: true, force: true });
  }
});
