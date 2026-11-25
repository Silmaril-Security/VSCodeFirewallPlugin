# Changelog

## 0.4.0 - Unreleased

- Move to `@silmaril-security/sdk` 1.0.0. The SDK calls `/v2/classify` on the
  unchanged `apiUrl` and falls back to `/classify` when a deployment answers
  403, 404, or 405, so configuration does not change. Each event uses a new
  client; a deployment without `/v2/classify` receives two requests per event
  inside the existing classification deadline.
- Treat every classify result whose `action` is not `allow` as an enforcement
  candidate. Model and governance blocks keep the same native outputs.
- Write the Firewall's `confidence` and `severity` labels to local evidence
  when the result carries a listed value, and stop writing `modelScore` and
  `modelThreshold`. The event schema version and every other field are
  unchanged. SilmarilMacOS releases that predate the labels ignore them.
- Record the SDK result's `modelId` as the local evidence `modelVersion` and
  the governance decision's `policyVersion` as `policyVersion`. The fields
  previously read `model_id` and a top-level `policy_version`, which the SDK
  never returned, so they were always absent. Both have control and format
  characters removed and are limited to 128 UTF-8 bytes, the limits Silmaril
  for macOS enforces on ingestion.
- Read the evidence risk class from the result `outcome`. An allow and a
  governance-only block carry no outcome and record `unknown`.
- A `/v2/classify` response carries no mode. Omitting both `mode` and
  `blockMalicious` selects `shadow` unless a version 1 response body, as the
  `/classify` fallback returns, supplies a mode.
- Serve `/v2/classify` and `/classify` from the native QA loopback classifier
  and cover the fallback and a version 1 body returned by `/v2/classify`.

## 0.3.3

- Bundle SDK 0.11.0, whose outcome taxonomy names the tenant acceptable-use
  policy outcome `abuse`, and which rejects classifier responses without a
  numeric `score` and `threshold` from 0 through 1. A rejected response is a
  classification error and returns `{}`.

## 0.3.2

- Released as [v0.3.2](https://github.com/Silmaril-Security/VSCodeFirewallPlugin/releases/tag/v0.3.2).
- Record the supplied workspace for validated shared Copilot
  `userPromptSubmitted` callbacks in both direct and dispatcher paths.
- Keep submitted-prompt callbacks classification-free and fail open when
  workspace observation fails.
- Supersede the unreleased 0.3.1 candidate.

## 0.3.1 - Unreleased

- Keep the submitted-prompt registration for VS Code Local, while shared
  Copilot submitted-prompt callbacks return without classification.
- Register `userPromptTransformed`, classify its exact model-facing bytes, and
  replace a Block candidate only through bounded `modifiedTransformedPrompt`.
- Preserve transformed content in Warn and Shadow and record transformed Warn
  delivery as unsupported.
- Correlate validated shared Copilot sessions through `conversationId` and add
  transformed-prompt identities based on the native event, timestamp, original
  prompt hash, and transformed prompt hash without changing other identities.
- Set the conservative source target and security-admission floor to VS Code
  1.145.2. It is not a qualified supported floor or a claim that 1.145.2 is
  the earliest possible upstream version. Signed 1.141.1 lacks the required
  transformed-prompt and post-tool replacement contracts.
- Require the synthetic native-QA launcher to select and verify ephemeral
  in-memory secret storage. Private profile directories do not isolate the
  macOS Keychain; this test-only correction does not change the plugin runtime.
- Make native QA portable across macOS hosts with a fresh owned synthetic
  profile, credential-free child environment, preflight-only default, and an
  explicit one-launch human workflow for normal trust and Extensions UI setup.
- Record that the exact signed 1.145.2 native matrix failed. The built-in Local
  route blocked the main malicious prompt and denied pre-tool execution, but a
  native title-generation request sent the blocked prompt before
  `UserPromptSubmit`, and the raw post-tool result reached the next dummy model
  request. The Local post-tool contract only appends block/context, and the
  signed host starts that async append without awaiting it.
- Keep the shared transformed-prompt and post-tool `modifiedResult` contracts
  source-only and unqualified until a supported shared Agent Host route proves
  them. Preserve strict all-provider/title and post-tool-poison oracles; do not
  publish candidate 0.3.1 on the failed native evidence.
- Require the four-case native core to prove exact shared callback metadata:
  `copilot/userPromptTransformed`, `copilot/preToolUse`, and
  `copilot/postToolUse`, each at its required cardinality. Local, missing,
  mixed, or wrong-event callbacks cannot satisfy shared-route acceptance.
- Scope any native QA `pass` to that four-case core. Receipts keep full release
  qualification incomplete, batch/resume unsupported, and native Warn/Shadow
  unassessed; source preflight cannot verify the native shared route. Candidate
  0.3.1 remains not qualified for publication.

The published 0.3.0 release remains immutable. Handler fixtures and loopback
checks do not establish native qualification.
