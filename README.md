# VS Code Firewall Plugin

Silmaril Firewall protection for Local and shared Copilot agent sessions in Visual Studio Code.

Plugin version 0.3.0 uses the Agent Plugins 1.0 package format and exact
`@silmaril-security/sdk` 0.8.2. The single active hook manifest registers the
shared Copilot camelCase events `sessionStart`, `userPromptSubmitted`,
`preToolUse`, and `postToolUse`. VS Code Local accepts those event aliases but
sends its documented PascalCase/snake_case payloads, so the launcher calls an
explicit dispatcher that validates and selects exactly one schema. The
exported `runVSCodeHook(PascalEvent, ...)` API and PascalCase CLI remain the
explicit legacy Local interface; `runVSCodeCopilotHook` is the explicit shared
runtime interface.

Copilot selection requires a nonempty `sessionId`, numeric epoch-millisecond
timestamp, and documented camelCase event fields. Local selection requires a
matching `hook_event_name`, ISO timestamp, and documented native snake_case
event fields; Local `session_id`, `cwd`, and `transcript_path` remain optional.
Missing required fields, mixed schemas, ambiguous inputs, or mismatched events
return `{}` without classification or protection evidence. Event casing,
filenames, selected models, and version strings are not runtime proofs.

Classification metadata keeps agent identity `vscode` and adds
`vscodeHookRuntime` (`local` or `copilot`). The hook classifies the current
prompt, stable tool arguments, or documented successful tool-result text
without reading transcripts.

## Requirements

Release [v0.3.0](https://github.com/Silmaril-Security/VSCodeFirewallPlugin/releases/tag/v0.3.0)
is available as the immutable source for this version. Installation remains a
managed local macOS operation owned by SilmarilMacOS, which adopts the exact
plugin payload into the paths below. The release is not a VS Code Marketplace
or npm distribution, and checking it out does not qualify direct GUI, remote,
or native-host protection.

SilmarilMacOS manages local installation and configuration. Plugin 0.3.0
requires macOS and Node.js 22 or newer. VS Code stable 1.145.2 is the shared
Copilot reference used for this update. Local support retains its VS Code 1.110
floor; no earliest shared-runtime minimum is claimed.

The manifest uses the portable `command` field, but `scripts/run-hook.sh`
intentionally supports only the managed macOS installation. On an unsupported
platform or with an unusable runtime it prints `{}` and exits 0. A Remote SSH
macOS host needs the plugin, Node path, and configuration on that host;
installation in local profiles does not prove remote execution.

The app installs the plugin at `~/.vscode/silmaril-firewall`, writes the private schema-v1 configuration to `~/.vscode/silmaril-firewall.json`, and registers the plugin through `chat.pluginLocations` in each local VS Code profile. `scripts/run-hook.sh` reads the Node binary from `~/.vscode/silmaril-firewall-node-path`. That path file must be a non-symlink mode `600` file owned by the current user, and its first line must be an absolute path to a non-symlink executable owned by root or the user, with mode `500`, `555`, `700`, `711`, `744`, or `755`. When the runtime file or binary fails those checks, the launcher prints `{}` and exits 0.

## Protection boundaries

`com.github.copilot/hooks/hooks.json` registers exactly one command for each of
the four camelCase events. Every command runs quoted
`${PLUGIN_ROOT}/scripts/run-hook.sh dispatch <event>` with `timeoutSec: 12`.
Stop, subagent lifecycle, failure, and compaction events are not registered.

Every registered event records a provided, resolvable absolute `cwd` in a bounded workspace registry (256 paths) at `~/Library/Application Support/Silmaril/VSCode/observed-workspaces.json`, or the path in `SILMARIL_VSCODE_WORKSPACE_STATE`. An absent Local `cwd` is accepted and produces no workspace observation. `SessionStart` then returns `{}`. The other three events classify the current payload:

| Boundary | Local field | Copilot field | SDK hook | Evidence `hook` |
| --- | --- | --- | --- | --- |
| Prompt | `prompt` | `prompt` | `user_input` | `user_input` |
| Before tool | `tool_input` | `toolArgs` | `tool_call` | `pre_tool` |
| Successful tool result | `tool_response` | `toolResult.textResultForLlm` | `tool_response` | `tool_result` |

`sessionStart` only records the bounded workspace observation and returns `{}`.
Every other valid event classifies exactly once. Empty classified text is
skipped.

### Runtime-specific outputs

Local outputs are unchanged: Warn returns the fixed warning through Local
continuation/context fields. Block stops a prompt, returns Local's nested tool
denial before execution, or returns the legacy post-tool block response.

Shared Copilot output follows the event-specific command-hook contract:

- `userPromptSubmitted` output is ignored. Block and Warn therefore return
  `{}`; evidence marks Block unavailable and Warn delivery unsupported.
- `preToolUse` Block returns top-level `permissionDecision: "deny"` with the
  fixed safe reason. Warn and benign results return `{}` without permission
  overrides or unsupported context.
- `postToolUse` Block returns `modifiedResult` with a successful result
  containing only the fixed safe block message. Warn returns supported
  `additionalContext`. Replacement changes model-facing result text and never
  claims to reverse a completed side effect.

Shadow always returns `{}`. Missing or invalid configuration, an unusable Node
runtime, malformed input, classification failures, and the bounded deadline
fail open with `{}`. Evidence failures never alter an otherwise valid native
output. Command hooks cannot by themselves establish native GUI protection;
verify the intended harness and installation in a disposable session.

## Configuration

A present schema-v1 configuration file is the only configuration source. `SILMARIL_CONFIG_PATH` selects it; otherwise the path is `~/.vscode/silmaril-firewall.json`. The file must declare `schemaVersion` 1, be a regular non-symlink file of at most 64 KiB, be owned by the current user, and have no group or world permission bits. `apiKey` and `apiUrl` are required. Optional fields are `enabled`, `endpointId`, `timeoutMs`, `mode`, legacy `blockMalicious`, and `debug`. File booleans are JSON booleans. `endpointId` is included only when it is a UUID version 4; any other string is ignored. `timeoutMs` defaults to 2500 when omitted and, when present, must represent an integer from 250 through 10000, supplied as either a JSON integer or a numeric string that converts to an integer in that range. SDK 0.8.2 applies that timeout to each classify attempt and retries HTTP 429 up to 5 times, waiting at most 30 seconds between attempts. A present field with the wrong type, aside from a numeric `timeoutMs` string that converts to an in-range integer, a `mode` outside `shadow`, `warn`, and `block`, or an out-of-range `timeoutMs` invalidates the file. `enabled: false` skips classification. An invalid file fail-opens.

Environment variables apply only when the file is absent: `SILMARIL_ENABLED`, `SILMARIL_API_KEY`, `SILMARIL_API_URL`, `SILMARIL_ENDPOINT_ID`, `SILMARIL_TIMEOUT_MS`, `SILMARIL_MODE`, `SILMARIL_BLOCK_MALICIOUS`, and `SILMARIL_DEBUG`. Those environment booleans accept `true`/`false`, `1`/`0`, `yes`/`no`, and `on`/`off`. Unrecognized boolean text is treated as an omitted value.

Explicit `mode` (`shadow`, `warn`, or `block`) is sent to the classifier and becomes the effective mode, ahead of a response mode of `shadow`, `warn`, or `block`, and ahead of `blockMalicious`. If `mode` is omitted and `blockMalicious` is true, the effective mode is `block`. If `mode` is omitted and `blockMalicious` is false, the effective mode is `shadow`. Omit both to use a response mode of `shadow`, `warn`, or `block`. A missing response mode is `shadow`. `@silmaril-security/sdk` 0.8.2 rejects any other response mode before evidence is written, and the hook then returns `{}`.

Prediction exactly `MALICIOUS`, or a returned governance `action` exactly `block` after the SDK accepts the governance object, makes the event an enforcement candidate. The shipped SDK 0.8.2 accepts only predictions `BENIGN` and `MALICIOUS`. A governance object is accepted only when `action` is `allow` or `block` and `policy_version` is a non-empty string. A governance object missing that version is a classification error and returns `{}` without evidence. Any other rejected prediction or governance value is a classification error and returns `{}`. `block` mode returns the runtime-specific enforcement output where supported, `warn` mode returns only the runtime-supported warning output, and `shadow` mode records policy decision `monitor` and returns `{}`.

Prompt governance context is agent `vscode` and resource kind `agent`. Tool
events use resource kind `tool`. A native tool name matching
`mcp__<server>__<tool>` uses the public SDK `mcp_tool` resource with
`parentId: <server>`. No parent or server is invented for other names. The
context is passed through `ClassifyOptions.governance`; SDK 0.8.2 owns
canonical top-level wire serialization, including wire `parent_id`.
`metadata.silmaril.governance` remains compatibility attribution only.

### Classification deadline

The configured timeout bounds the entire classification, including throttling retries and response reads. Classification is capped at 8 seconds to leave time for hook output before the host deadline. Deadline errors follow the existing hook error behavior.


## Provenance and local evidence

Classify metadata `silmaril.provenance` is schema version 1, harness `vscode`, the configured `endpoint_id` when it is a UUID version 4, and `device_name` when a sanitized Mac ComputerName is available. A failed or invalid ComputerName lookup is omitted and classification continues. The SDK records `sdk_language` `typescript`, `sdk_version` `0.8.2`, and the stable hook request ID next to that provenance. Local evidence stores fingerprints, decision availability, bounded risk metadata, runtime-native action (`block_returned`, `content_replaced`, warning context, or allowed), and provenance producer `VSCodeFirewallPlugin` at plugin version 0.3.0. This distinguishes a pre-tool native denial from post-tool model-facing content replacement. Local evidence omits raw prompts, tool arguments, results, responses, credentials, and the computer name. Events are written under `~/Library/Application Support/Silmaril/Evidence/incoming`, or `SILMARIL_LOCAL_EVENT_DIR`, or `SILMARIL_EVIDENCE_ROOT/incoming`. VS Code's own Agent Debug logs remain host-owned behavior.

## Develop

The npm package `@silmaril/vscode-firewall-plugin` is private. `plugin.json`
name is `silmaril-vscode-firewall` at version 0.3.0, the same version as
`package.json` and `PLUGIN_VERSION`. The committed bundle includes SDK 0.8.2;
its bundled license is reproduced in `THIRD_PARTY_LICENSES.md`.

```sh
npm ci
npm run typecheck
npm test
npm run build
npm run pack:dry
```

`npm test` runs `scripts/build.mjs` (Node 22 bundle) and then the tests. The built `dist/vscode-hook.js` file is committed because VS Code executes the plugin directly from its installed directory. CI rejects a bundle that does not match a rebuild.

Primary contracts used for this implementation:

- [GitHub Copilot hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)
- [VS Code hooks](https://code.visualstudio.com/docs/agent-customization/hooks)
- [VS Code hook migration guide](https://code.visualstudio.com/docs/agent-customization/migrate-customizations)
- [VS Code Agent Plugins](https://code.visualstudio.com/docs/agent-customization/agent-plugins)
- [Legacy Local hooks reference](https://code.visualstudio.com/docs/agents/reference/hooks-reference)
