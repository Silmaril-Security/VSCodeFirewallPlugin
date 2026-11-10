# Changelog

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
