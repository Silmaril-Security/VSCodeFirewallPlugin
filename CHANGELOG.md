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
- Set the candidate support floor to VS Code 1.141.1 and require exact native
  qualification on 1.141.1 and 1.145.2 before publication.

The published 0.3.0 release remains immutable. Handler fixtures and loopback
checks do not establish native qualification.
