import { mkdir } from "node:fs/promises";
import { build } from "esbuild";

await mkdir(new URL("../dist", import.meta.url), { recursive: true });
await build({
  entryPoints: [new URL("../src/vscode-hook.ts", import.meta.url).pathname],
  outfile: new URL("../dist/vscode-hook.js", import.meta.url).pathname,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  external: ["@langchain/core/callbacks/base"],
  legalComments: "none",
  sourcemap: false,
});

