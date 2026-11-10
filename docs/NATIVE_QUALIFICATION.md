# Native VS Code qualification

This is the required native acceptance procedure for candidate 0.3.1. Unit,
loopback, source, archive, and generated-output checks are not substitutes for
this procedure.

## Current qualification status

The exact signed 1.145.2 native matrix **failed**. No native pass has been
recorded, and candidate 0.3.1 is not qualified for publication.

- VS Code 1.141.1 (`7baac39ec3ca969dab74ac12c097f6a486e46593`,
  built-in Copilot Chat 0.69.0) is unsupported. Its exact signed source lacks
  the transformed-prompt replacement and post-tool `modifiedResult`
  replacement contracts. It must not be launched or treated as compatibility
  evidence.
- VS Code 1.145.2 (`c4453f8ea430795f941c1b2ff6c9321135a74a02`,
  built-in Copilot Chat 0.73.0) is the conservative source target and
  security-admission floor. It is not a qualified supported floor or a claim
  that it is the earliest possible upstream version.
- Native batch/resume is unsupported. Neither exact build exposes a public,
  version-matched queue/resume interface; history injection is not resume
  evidence.

The signed 1.145.2 Local route blocked the main malicious agent prompt and
denied pre-tool execution. It nevertheless failed two unchanged acceptance
oracles:

1. a native title-generation provider request sent the full blocked prompt
   before the Local `UserPromptSubmit` hook; and
2. a raw blocked post-tool result remained in the next dummy-model request.

The retained hook log shows that `PostToolUse` started before the strict suite
failure but had not finished when the suite stopped. The signed built-in
source starts its async context append without awaiting it, and its Local
contract appends block/context to the original result rather than replacing
the result. This is a timing and host-contract limitation, not evidence that
the callback was never invoked. The shared `modifiedResult` contract is
source-only and unqualified because this matrix did not exercise a supported
shared Agent Host route.

The receipt's top-level result is explicitly scoped to a four-case native core:
allow, prompt block, pre-tool block, and post-tool block. Every receipt,
including preflight and failure receipts, separately records full release
qualification as `incomplete`, batch/resume as `unsupported`, native
Warn/Shadow as `unassessed`, and the shared route as `unverified` until exact
callback metadata proves it. A four-case core pass would not be a full release
matrix pass or qualify candidate 0.3.1 for publication.

The relevant official source at the exact commit is:

- [`agentHostTurnStarter.ts`](https://github.com/microsoft/vscode/blob/c4453f8ea430795f941c1b2ff6c9321135a74a02/src/vs/platform/agentHost/node/agentHostTurnStarter.ts)
  and
  [`agentHostSessionTitleController.ts`](https://github.com/microsoft/vscode/blob/c4453f8ea430795f941c1b2ff6c9321135a74a02/src/vs/platform/agentHost/node/agentHostSessionTitleController.ts)
  for the Agent Host turn/title paths;
- [`toolCalling.tsx`](https://github.com/microsoft/vscode/blob/c4453f8ea430795f941c1b2ff6c9321135a74a02/extensions/copilot/src/extension/prompts/node/panel/toolCalling.tsx)
  and
  [`chatHookService.ts`](https://github.com/microsoft/vscode/blob/c4453f8ea430795f941c1b2ff6c9321135a74a02/extensions/copilot/src/extension/chat/vscode-node/chatHookService.ts)
  for the built-in Local post-tool path; and
- [`copilotPluginConverters.ts`](https://github.com/microsoft/vscode/blob/c4453f8ea430795f941c1b2ff6c9321135a74a02/src/vs/platform/agentHost/node/copilot/copilotPluginConverters.ts)
  for the distinct shared replacement contract.

The 1.145.2 qualification gates these reviewed identities:

| Item | Required value |
| --- | --- |
| Apple team | `UBF8T346G9` |
| Workbench source SHA-256 | `8bd0d70cda8542f514a45534a14860ea48ddf39f149036838aebfcf2cc6ba02a` |
| Copilot manifest SHA-256 | `d0e92ec15928120112abbe0d45ce3b4a3c1051562421044848ee3dee014f0874` |
| Copilot source SHA-256 | `e8db5deec0a8fda393769d44c5f99ec29bd687f4e0e05f6b36e99e606f6efed0` |

## Isolation and safety boundaries

Every invocation creates one new synthetic profile root. The root must not
already exist; its parent must be a real, nonsymlinked directory owned by the
current user. The harness creates the root with mode `0700` and keeps its
`HOME`, user data, extensions, workspace, temporary files, callbacks, logs,
and receipt inside that root.

Before creating the root, the harness also checks the exact VS Code main IPC
handle `<root>/user-data/1.14-main.sock`. Its full path must be at most 103
UTF-8 bytes on macOS. Use a short real path under `/private/tmp`; `/tmp`
resolves to `/private/tmp` and is not itself accepted as a real parent path.
The owned, nonsymlinked parent must already exist. Do not use a symlink alias
to shorten the spelling.

The child environment is an allowlist. It does not inherit caller AWS, GitHub,
package-registry, model-provider, or vendor credentials. The profile uses a
unique synthetic device ID and never reads a host profile.

`--use-inmemory-secretstorage` is mandatory. A private `HOME` and
`--user-data-dir` do not isolate the macOS Keychain. Before trust or chat, the
extension-test harness must prove:

- the launch flag was selected;
- the in-memory secret service was selected; and
- no OS-encryption probe was observed.

Missing or failed isolation stops the owned process group. Do not replace this
with `--password-store=basic`, plaintext credentials, Keychain reset/unlock,
workspace-trust bypass, sandbox disablement, an extra Copilot development
path, hidden enablement commands, or enablement-database edits.

The exact signed 1.145.2 source proves the route through:

- `out/mainImpl.js`
  (`bc1301b3269f645df36d12d424cdbbf35a3930076914bd77229df45394352896`);
- `out/vs/code/electron-utility/sharedProcess/sharedProcessMain.js`
  (`abba4fd10109a1f69cff33bfa49b778bb2dfa4667d711f6cfb727dc6d43847c8`);
- `out/vs/workbench/workbench.desktop.main.js`
  (`8bd0d70cda8542f514a45534a14860ea48ddf39f149036838aebfcf2cc6ba02a`);
- `out/vs/workbench/api/node/extensionHostProcess.js`
  (`f1942dd49181aecdad6caabc5bbf2514d76a07032caf447e32bc5694f22d5dcb`);
- `extensions/github-authentication/dist/extension.js`
  (`fc0ca5e540f0496675941af9eb359441ae4cb9267766a5fff5c46c38f3ec2ec0`).

The launcher performs a JavaScript missing-identifier preflight over every
native CJS suite/support file before any launch. Its regression oracle mutates
an in-memory source copy to prove the check detects an undefined helper.

## Portable commands

The npm command is preflight-only by default and cannot launch the VS Code GUI
or extension-test host. Use a new root for every invocation:

```sh
QA_PARENT="$(mktemp -d /private/tmp/svqa.XXXXXX)"
QA_ROOT="$QA_PARENT/p-$$"
chmod 700 "$QA_PARENT"

VSCODE_APP="/absolute/path/to/verified/Visual Studio Code.app" \
VSCODE_NATIVE_PRIVATE_ROOT="$QA_ROOT" \
NATIVE_QUALIFICATION_RECEIPT="$QA_ROOT/evidence/qualification.json" \
npm run test:native:vscode
```

Preflight verifies the exact app identity, signature, source contracts,
secret-storage route, UI action guards, native CJS files, and candidate 0.3.1
bytes. It writes `source-pass` for admitted source target 1.145.2 without
spawning a GUI. `source-pass` is not a native or supported-floor result and
cannot mark the shared route verified.

Only a separately reviewed human run may set the explicit gate below. It
requires three distinct absolute marker paths inside the same fresh root and
contains exactly one application launch with no automatic retry:

```sh
QA_PARENT="$(mktemp -d /private/tmp/svqa.XXXXXX)"
QA_ROOT="$QA_PARENT/n-$$"
chmod 700 "$QA_PARENT"

VSCODE_APP="/absolute/path/to/verified/Visual Studio Code.app" \
VSCODE_NATIVE_PRIVATE_ROOT="$QA_ROOT" \
NATIVE_QUALIFICATION_RECEIPT="$QA_ROOT/evidence/qualification.json" \
SILMARIL_VSCODE_QA_ALLOW_HUMAN_UI=1 \
NATIVE_TRUST_PENDING_PATH="$QA_ROOT/handoffs/workspace-trust.json" \
NATIVE_AGENT_ENABLE_PENDING_PATH="$QA_ROOT/handoffs/disable-ai.json" \
NATIVE_WORKSPACE_AI_ENABLE_PENDING_PATH="$QA_ROOT/handoffs/enable-ai-workspace.json" \
npm run test:native:vscode
```

The coordinator performs only these normal UI actions, in marker order:

1. After the isolation receipt passes and the trust marker appears, accept
   normal workspace trust for the displayed synthetic workspace.
2. After the phase-1 marker appears, use the bundled Copilot extension's
   normal Extensions menu and select **Disable AI Features**.
3. After the phase-2 marker appears, select
   **Enable AI Features (Workspace)**.

Do not install an extension, sign in, accept terms, start chat setup, select a
real provider, execute a disabled command, or interact with another window.
If any normal UI action is unavailable or requests an account, entitlement,
credential, or real provider, stop and retain the failure receipt.

The source-verified two-phase transition writes only
`chat.disableAIFeatures=true` in private synthetic profile settings, followed
by `settings.chat.disableAIFeatures=false` in the synthetic workspace file.
The harness observes public configuration and extension events and then
requires ordinary registration of exact built-in `github.copilot-chat`
0.73.0 at the signed application path with the hashes above.

After the owned app and children exit, the harness archives each changed
synthetic settings/config/workspace file, classifies the exact delta, and
restores all three generated baselines byte-for-byte. Restoration opens all
three destinations with no-follow semantics and validates owner, regular-file
type, inode, and root containment before the first write. Any unexpected
delta, path substitution, restoration error, server-cleanup error, or
unsettled owned process forces a failed receipt and nonzero result.

Restoration additionally requires bounded proof that the entire captured
detached process group is absent; main-process exit alone is insufficient.
After the TERM grace period, cleanup waits for group absence after KILL and
fails without restoring if identity, inspection, termination, or absence
cannot be proved. Classifier and proxy cleanup tracks accepted sockets and
both CONNECT peers and has a bounded close deadline.

Provider requests and synthetic tool invocation counts are also fsynced as
append-only private NDJSON observations while they occur. These rows are
explicitly in-progress and unfinished. Their integrity and retained trailing
partial line are recorded on every native-launch outcome, but they never
replace the finished provider capture or satisfy a native acceptance oracle.

## Full release acceptance matrix

The current native harness executes only the four-case core described above.
For full release qualification on exact signed 1.145.2, the deterministic
local provider and synthetic tools must prove:

1. one candidate plugin location and one callback per manifest event;
2. `sessionStart` records workspace registration without classification;
3. submitted shared prompt performs zero classifications and transformed
   prompt performs exactly one over exact untrimmed bytes;
4. benign transformed prompt reaches the dummy provider unchanged;
5. malicious transformed prompt reaches the dummy provider only as the fixed
   safe replacement, without claiming turn rejection;
6. Local `UserPromptSubmit` still performs one classification and native
   blocking;
7. blocked pre-tool use invokes one callback and creates no side-effect marker;
8. blocked post-tool use reaches the next provider request only as the fixed
   safe replacement, with the synthetic poison absent;
9. Warn and Shadow transformed prompts return `{}`, with Warn explicitly
   unsupported for transformed-prompt delivery; and
10. malformed and classifier-failure paths fail open without protection
    claims.

The provider-disclosure checks cover every provider request, including native
title metadata requests. The post-tool check searches all subsequent provider
message values for the raw synthetic poison. Title requests must not be
filtered out, and appended warning/context must not be mistaken for
replacement.

For the four-case core itself, each required classifier callback must also
prove the shared route through exact metadata. All four `user_input` callbacks
must be `vscodeHookRuntime=copilot` and
`vscodeHookEvent=userPromptTransformed`; the required `tool_call` and
`tool_response` callbacks must respectively be `copilot/preToolUse` and
`copilot/postToolUse`, each exactly once. Local, mixed, absent, or wrong-event
metadata fails the core rather than satisfying shared callback counts.

All model calls are served by the unique deterministic contributed dummy
provider. The anonymous no-auth GitHub control-plane request is allowed only
through the recording loopback proxy. Any real model/provider destination,
account, token, credential, or host profile access is a hard stop.

Retain the app identity, source hashes, candidate hashes, isolation receipt,
safe extension inventory, loopback classifier requests, outbound
destinations, exact provider captures, marker checks, process identity, logs,
file-delta archives, cleanup state, and final receipt. Partial execution
and failed execution remain failed and cannot establish native qualification.

## Managed macOS propagation

The candidate admission floor is 1.145.2, but it is not a qualified supported
floor. Publication and managed propagation remain gated on a native matrix
pass that preserves the strict title-request and post-tool-poison oracles. The
shared transformed-prompt and `modifiedResult` contracts remain source-only
until a supported shared Agent Host route proves them. Do not publish 0.3.1 or
modify or relabel 0.3.0.
