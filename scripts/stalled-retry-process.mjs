import * as hook from "../dist/vscode-hook.js";
hook.__testInternals?.installDeviceNameLookupForTests({ platform: "linux" });
let attempts = 0;
globalThis.fetch = async () => ++attempts < 3
  ? new Response("throttled", { status: 429 })
  : new Response(new ReadableStream({ cancel: () => new Promise(() => {}) }), { status: 429 });
const env = process.env;
const started = performance.now();
await hook.runVSCodeHook("UserPromptSubmit", { prompt: "synthetic test" }, env);
console.log(JSON.stringify({ attempts, hookMS: performance.now() - started }));
