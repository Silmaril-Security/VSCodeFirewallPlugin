# VS Code Firewall Plugin

Silmaril Firewall protection for local agent sessions in Visual Studio Code.

The plugin uses VS Code's Agent Plugins 1.0 hook contract, so one installation covers the Local, Copilot, Claude, and Codex harnesses when they execute on the local Mac. It classifies the current user prompt, tool call, or successful tool response without reading the unstable transcript file.

Shadow classifies silently. Warn preserves the event and returns one fixed, content-free warning. Block stops a submitted prompt, denies a tool before execution, or stops further processing after a completed tool. A PostToolUse block never claims that the completed side effect was undone. Missing configuration, unavailable Node, API failures, malformed inputs, and timeouts fail open.

## Requirements

SilmarilMacOS manages installation and configuration. Version 1 requires macOS, VS Code 1.110 or newer, and Node.js 22 or newer. Remote SSH, development containers, Windows, Linux, and cloud harness execution are not covered.

The app installs the plugin at `~/.vscode/silmaril-firewall`, writes the private schema-v1 configuration to `~/.vscode/silmaril-firewall.json`, and registers the plugin through `chat.pluginLocations` in each local VS Code profile.

## Protection boundaries

`UserPromptSubmit` maps to `user_input`, `PreToolUse` maps to `tool_call`, and `PostToolUse` maps to `tool_response`. SessionStart records only a bounded local workspace observation for MCP inventory. Stop, subagent lifecycle, and compaction payloads do not expose current model content, so this plugin does not reconstruct it from `transcript_path`.

Omit `mode` to use the backend-selected mode, or set `shadow`, `warn`, or `block`. Explicit mode wins over backend mode and the legacy `blockMalicious` field. Exact `MALICIOUS` predictions and governance Block actions are enforcement candidates.

Local evidence contains fingerprints, decisions, bounded risk metadata, and version provenance. It never stores raw prompts, tool arguments, results, responses, or credentials. VS Code's own Agent Debug logs remain host-owned behavior.

## Develop

```sh
npm ci
npm run typecheck
npm test
npm run pack:dry
```

The built `dist/vscode-hook.js` file is committed because VS Code executes the plugin directly from its installed directory.

Silmaril Firewall protection for local VS Code agent harnesses.
