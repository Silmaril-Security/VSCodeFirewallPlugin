# Native VS Code qualification

This is the required native acceptance procedure for candidate 0.3.1. Unit
fixtures, direct launcher execution, generated output, source inspection, and
the SilmarilMacOS pinned-host job are not substitutes: the current pinned-host
job has no VS Code driver.

## Preconditions

- Use separate, verified VS Code application copies whose `code --version`
  output is exactly `1.141.1` and `1.145.2`. Record the complete version output
  and application digest. Reject every other version; in particular, the
  installed 1.145.0 application cannot qualify either target.
- Use a disposable `HOME`, `--user-data-dir`, `--extensions-dir`, workspace,
  and evidence directory. Do not read or change host user data, settings,
  credentials, extensions, or the managed Silmaril installation.
- Copy the reviewed candidate archive into the disposable home and register
  only that copy through the isolated profile's `chat.pluginLocations`.
- Use a deterministic loopback classification stub and synthetic unique
  markers. Do not call a live model, Firewall deployment, or customer service.
- Use a supported no-inference native chat driver. If the required UI,
  authentication-independent driver, or accessibility permission is
  unavailable, stop and record the missing capability; do not replace the
  native run with simulated hook calls.

## Exact matrix

Run every case independently on 1.141.1 and 1.145.2:

1. Confirm the host loads one candidate plugin location and exactly one command
   for each manifest event. Confirm Local and shared registrations do not
   dispatch the same native callback twice.
2. Shared `sessionStart`: observe workspace registration and no classification.
3. Shared submitted prompt followed by transformed prompt: observe zero
   classifications for `userPromptSubmitted`, one for
   `userPromptTransformed`, exact untrimmed transformed bytes at the loopback
   stub, and one stable request identity.
4. Benign transformed prompt: observe no hook output mutation and unchanged
   model-facing bytes.
5. Block-mode transformed prompt: observe only
   `modifiedTransformedPrompt` with the fixed safe message. Confirm the
   malicious marker is absent from the downstream model-input capture and the
   turn is not reported as rejected.
6. Batched preceding and primary prompts: observe one classification per
   transformed callback, distinct deterministic identities, and no submitted
   prompt duplicate. Resume and confirm the already replaced safe content is
   replayed without reintroducing the marker.
7. Local `UserPromptSubmit`: observe one classification and the existing
   native prompt block. This proves retaining `userPromptSubmitted` did not
   remove Local protection.
8. Shared `preToolUse`: use a synthetic tool whose only side effect is creation
   of a marker in the disposable workspace. In Block mode, confirm native deny
   output and that the marker was not created.
9. Shared `postToolUse`: return a synthetic secret marker from a side-effect-free
   tool. In Block mode, confirm the model-facing result contains only the fixed
   replacement and the original marker is absent downstream.
10. Warn and Shadow: confirm transformed prompts return `{}`. Confirm Warn is
    recorded as unsupported for transformed prompts and does not claim prompt
    blocking.
11. Failure paths: stop the loopback stub and provide malformed mixed schemas.
    Confirm `{}`, no protection evidence for rejected schemas, and no claim of
    native enforcement.

Retain raw synthetic host logs, stub request logs, output captures, marker
checks, candidate archive digest, manifest digest, and a summary that names the
exact application version and architecture. A pass requires all cases on both
versions. Partial execution stays `unverified`.

## Managed macOS propagation

After both exact native runs pass, the SilmarilMacOS owner must:

1. Propagate the reviewed 0.3.1 event, validation, identity, and output contract
   into the managed signed runtime and its separately hashed manifest. The
   managed manifest invokes `SilmarilHookRuntime`; it is not byte-identical to
   the standalone `run-hook.sh` manifest.
2. Set `VSCodeHostController.minimumVSCodeVersion` and the generated integration
   manifest minimum to `1.141.1`.
3. Add controller tests accepting 1.141.1 and 1.145.2 and rejecting 1.141.0
   and representative earlier versions.
4. Verify unsupported status preserves the configured protection state and
   cannot install or activate the adapter.
5. Update adapter version, required artifact hashes, generated manifest,
   public support documentation, and signed-artifact expectations together.
6. Reference the native receipts by digest. Do not relabel 0.3.0 or any
   previously signed artifact.
