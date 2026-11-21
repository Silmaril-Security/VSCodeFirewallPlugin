"""Run one ordinary Read through the signed editor and the installed firewall adapter."""
import contextlib
import hashlib
import hmac
import json
import os
from pathlib import Path
import plistlib
import pwd
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

from macos_release_lease import PhysicalHostUnavailable


ROUTE = "agent-host-copilotcli"
EVIDENCE = Path("Library/Application Support/Silmaril/Evidence/incoming")
DATA = Path("Library/Application Support/Code")
GUARD = Path("/Users/Shared/silmaril-release-qa/vscode-qa-identity.json")
DENIALS = {"prompt_denial": ("user_input", "content_replaced"),
           "pre_tool_denial": ("pre_tool", "block_returned"),
           "post_tool_denial": ("tool_result", "content_replaced")}
BLOCK_MESSAGE = "Silmaril Firewall blocked potentially malicious content."
VERSIONS = {True: "1.145.3", False: "1.145.2"}


def prerequisite(ok, message):
    if not ok:
        raise PhysicalHostUnavailable(message)


def run(*args, **kwargs):
    return subprocess.run(args, check=True, stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=45, **kwargs)


def read_json(path):
    return json.loads(path.read_bytes())


def qa_directories():
    """The operator binds the dedicated Aqua account and its normally trusted workspace once."""
    try:
        info = GUARD.lstat()
    except FileNotFoundError:
        raise PhysicalHostUnavailable("Provision the VS Code QA account and profile descriptor") from None
    prerequisite(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
                 and info.st_nlink == 1, "Untrusted QA account descriptor")
    identity = read_json(GUARD)
    user = pwd.getpwuid(os.getuid())
    prerequisite(user.pw_uid and identity["account"] == user.pw_name,
                 "Physical runner must be the designated QA user")
    groups = run("/usr/bin/id", "-Gn", user.pw_name).stdout.split()
    prerequisite(b"admin" not in groups and Path("/dev/console").stat().st_uid == user.pw_uid,
                 "The designated standard QA user must own the active Aqua console")
    root = Path(user.pw_dir)
    paths = []
    for key in ("profileTemplate", "workspace"):
        directory = Path(identity[key])
        prerequisite(directory.is_relative_to(root) and directory != root and directory.is_dir()
                     and directory.resolve() == directory and directory.stat().st_uid == user.pw_uid,
                     "The designated QA workspace and seed profile must be real, owned directories")
        paths.append(directory)
    prerequisite(paths[0] != paths[1] and not any(p in q.parents for p, q in (paths, paths[::-1])),
                 "Use separate QA workspace and seed profile directories")
    return root, *paths


def verify_editor(managed):
    version = VERSIONS[managed]
    # Two releases can coexist; admit only an Apple-verified Microsoft signed app at the exact version.
    options = [Path(f"/Applications/VSCode-QA-{version}.app"), Path("/Applications/Visual Studio Code.app")]
    for app in options:
        if app.resolve() != app or not app.is_dir():
            continue
        with (app / "Contents/Info.plist").open("rb") as stream:
            info = plistlib.load(stream)
        if (info.get("CFBundleIdentifier"), info.get("CFBundleShortVersionString")) != ("com.microsoft.VSCode", version):
            continue
        run("/usr/bin/codesign", "--verify", "--deep", "--strict", app)
        rule = '=anchor apple generic and identifier "com.microsoft.VSCode" and certificate leaf[subject.OU] = "UBF8T346G9"'
        run("/usr/bin/codesign", "--verify", "--strict", "-R", rule, app)
        run("/usr/sbin/spctl", "--assess", "--type", "execute", app)
        return app / "Contents/MacOS" / info["CFBundleExecutable"], app / "Contents/Resources/app/bin/code"
    raise PhysicalHostUnavailable(f"Provision signed Microsoft VS Code {version} in /Applications")


def stage_profile(template, target, plugin):
    """Copy only the closed QA seed's settings and workbench state, leaving the seed untouched."""
    def copy(relative):
        src = template / relative
        prerequisite(src.is_file() and src.resolve() == src, f"QA profile missing {relative}")
        to = target / relative
        to.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(src, to)
        to.chmod(0o600)
    # This state carries normal workspace trust, QA account and prior shared-harness selection.
    copy(Path("User/globalStorage/state.vscdb"))
    storage = template / "User/workspaceStorage"
    if storage.is_dir() and storage.resolve() == storage:
        for workspace in storage.iterdir():
            if not (workspace / "workspace.json").is_file():
                continue
            for name in ("workspace.json", "state.vscdb"):
                copy(Path("User/workspaceStorage") / workspace.name / name)
    settings = template / "User/settings.json"
    prerequisite(settings.is_file() and settings.resolve() == settings, "QA seed settings.json required")
    values = read_json(settings)
    # Register exactly the release payload using the customer's standard editor setting.
    values.update({"chat.plugins.enabled": True, "chat.pluginLocations": {str(plugin): True},
                   "update.mode": "none", "extensions.autoUpdate": "off", "telemetry.telemetryLevel": "off"})
    (target / "User/settings.json").write_text(json.dumps(values))


def renderer_state(data, since):
    """Use the signed renderer's fresh completion record on the same shared chat resource."""
    rows, resources = [], set()
    for path in (data / "logs").glob("*/window*/renderer.log"):
        if path.resolve() != path:
            continue
        with path.open(errors="replace") as stream:
            for line in stream:
                if f"vscode-chat-session://{ROUTE}/" in line:
                    resources.add(path)
                marker = "[ChatTTFP] end "
                if marker not in line:
                    continue
                try:
                    row = json.loads(line.split(marker, 1)[1])
                except ValueError:
                    continue
                if (row.get("interactionKind") == "turn" and isinstance(row.get("epochMs"), (float, int))
                        and row["epochMs"] >= since):
                    rows.append((row, path))
    if len(rows) > 1:
        raise ValueError("Expected exactly one completed QA chat turn")
    if not rows:
        return None
    row, path = rows[0]
    if row.get("sessionType") != ROUTE or not str(row.get("chatSessionId", "")).startswith(ROUTE + ":/"):
        raise ValueError("Chat executed in the wrong VS Code session type")
    return row["chatSessionId"].split(":/", 1)[1].strip("/") if path in resources else None


def read_tool(event):
    name = (event.get("toolDisplayName") or "").replace("_", "").replace(" ", "").lower()
    return name in {"read", "readfile", "view"}


def valid_evidence(events, *, prompt, marker, version, managed):
    """Bind a real user prompt and both Read callbacks to one plugin version and one fresh session."""
    producer = "SilmarilHookRuntime" if managed else "VSCodeFirewallPlugin"
    expected = hashlib.sha256((prompt if managed else marker).encode()).hexdigest()
    rows = [e for e in events if e.get("host") == "vscode" and e.get("schemaVersion") == 1
            and e.get("provenance", {}).get("pluginVersion") == version
            and e.get("provenance", {}).get("producer") == producer]
    sessions = {e.get("sessionFingerprint") for e in rows if e.get("requestFingerprint") == expected
                and e.get("hook") == "user_input" and e.get("sessionFingerprint")}
    if len(sessions) != 1:
        return False
    matching = [e for e in rows if e.get("sessionFingerprint") in sessions]
    for event in matching:
        if (event.get("mode"), event.get("prediction"), event.get("policyDecision"), event.get("nativeAction")) != ("block", "benign", "allow", "allowed"):
            raise ValueError("The firewall did not allow the benign editor journey")
    reads = {e.get("hook") for e in matching if read_tool(e)}
    return {"pre_tool", "tool_result"}.issubset(reads)


@contextlib.contextmanager
def launch(binary, cli, profile, workspace, env):
    flags = [f"--user-data-dir={profile}", f"--extensions-dir={profile.parent / 'qa-extensions'}"]
    proc = subprocess.Popen([binary, *flags, "--new-window", "--skip-welcome", "--skip-release-notes",
                             "--log", "trace", workspace], env=env, cwd=workspace, start_new_session=True,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            prerequisite(proc.poll() is None, "Signed editor exited during launch")
            if any("Started local extension host with pid" in f.read_text(errors="replace")
                   for f in (profile / "logs").glob("*/window*/renderer.log")):
                break
            time.sleep(1)
        else:
            raise PhysicalHostUnavailable("The signed editor did not open an Aqua window")
        yield lambda prompt: run(cli, "chat", "--reuse-window", "--mode", "agent", prompt, env=env, cwd=workspace)
    finally:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)
        except ProcessLookupError:
            pass


def verify_managed_endpoint(url, key):
    # Signed native runtimes give device management precedence over the staged
    # local config. Only the intended tenant can supply this run's evidence.
    policy = Path("/Library/Managed Preferences/dev.silmaril.SilmarilMacOS.plist")
    try:
        metadata = policy.lstat()
    except FileNotFoundError:
        return
    prerequisite(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and not metadata.st_mode & 0o022,
                 "Untrusted managed policy file")
    try:
        with policy.open("rb") as stream:
            forced = plistlib.load(stream)
    except (OSError, plistlib.InvalidFileException) as error:
        raise PhysicalHostUnavailable("Cannot verify the managed Test Tenant binding") from error
    expected = {"silmaril.apiURL": url, "silmaril.apiKey": key}
    for name, value in expected.items():
        if name in forced:
            actual = forced[name]
            prerequisite(isinstance(actual, str) and hmac.compare_digest(actual.encode(), value.encode()),
                         "Device policy selects a different Test Tenant connection")


def journey(home, plugin, managed, version, checks):
    account_home, seed, workspace = qa_directories()
    binary, cli = verify_editor(managed)
    profile = home / DATA
    stage_profile(seed, profile, plugin)
    url = os.environ.get("CUSTOMER_NATIVE_API_URL", "")
    key = os.environ.get("CUSTOMER_NATIVE_API_KEY", "")
    target = urlsplit(url)
    prerequisite(target.scheme == "https" and target.hostname and not target.username and not target.password and key,
                 "A dedicated HTTPS Test Tenant endpoint and key are required")
    if managed:
        verify_managed_endpoint(url, key)
        prerequisite(not (account_home / ".vscode/silmaril-firewall.json").exists(),
                     "The dedicated QA account has a conflicting persistent firewall configuration")
    # The release job holds the cross-repository physical lock. Isolate the product config and editor data.
    config = home / ".vscode/silmaril-firewall.json"
    with config.open("x", opener=lambda name, flags: os.open(name, flags, 0o600)) as f:
        json.dump({"schemaVersion": 1, "enabled": True, "apiKey": key, "apiUrl": url, "mode": "block", "timeoutMs": 8000}, f)
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8",
           "HOME": str(home), "USER": pwd.getpwuid(os.getuid()).pw_name, "TMPDIR": str(home),
           # The chat subcommand rejects --user-data-dir. The CLI and Electron both resolve
           # VSCODE_APPDATA/Code to this run's profile and single-instance socket.
           "VSCODE_APPDATA": str(profile.parent),
           "SILMARIL_CONFIG_PATH": str(config)}
    if managed:
        env.update(SILMARIL_API_URL=url, SILMARIL_API_KEY=key, SILMARIL_MODE="block")
    spool_dirs = {home / EVIDENCE}
    if managed:
        # Foundation can select the dedicated QA login's Application Support directory.
        spool_dirs.add(account_home / EVIDENCE)
    pattern = "runtime-*.json" if managed else "event-*.json"
    # The signed Copilot Agent Host stores its normal session history under COPILOT_HOME/session-state.
    copilot = home / ".copilot"
    env["COPILOT_HOME"] = str(copilot)
    with launch(binary, cli, profile, workspace, env) as submit:
        for scenario in ("allow", *DENIALS):
            try:
                outcome = run_case(scenario, workspace, profile, copilot, spool_dirs, pattern,
                                   submit, managed, version)
            except PhysicalHostUnavailable as exc:
                print(str(exc), file=sys.stderr)
                outcome = "BLOCKED"
            except ValueError as exc:
                print(f"{scenario}: {exc}", file=sys.stderr)
                outcome = "FAIL"
            if scenario == "allow":
                checks["native"] = outcome
                checks["live"] = outcome
                if outcome != "PASS":
                    return
                checks["install"] = "PASS"
            else:
                checks[scenario] = outcome
        observed = [checks[scenario] for scenario in DENIALS]
        checks["policy_denial"] = ("FAIL" if "FAIL" in observed else
                                   "PASS" if all(s == "PASS" for s in observed) else "BLOCKED")


def session_history(copilot, session, offsets):
    # Only the scoped QA session's ordinary appended public client history is inspected.
    # No logging of text, no provider/network observer and no reading previous turns.
    if not session or "/" in session or session in {".", ".."}:
        return []
    path = copilot / "session-state" / session / "events.jsonl"
    if not path.is_file() or path.resolve() != path:
        return []
    with path.open("rb") as f:
        f.seek(offsets.get(path, 0))
        data = f.read(4 * 1024 * 1024 + 1)
    if len(data) > 4 * 1024 * 1024:
        raise PhysicalHostUnavailable("The bounded QA session-history observer could not read this turn")
    rows = []
    for line in data.splitlines():
        try:
            row = json.loads(line)
            if isinstance(row, dict) and isinstance(row.get("data"), dict):
                rows.append(row)
        except ValueError:
            continue  # the Agent Host may still be appending its final event
    return rows


def denial_observed(events, history, *, scenario, prompt, marker, version, managed, word):
    boundary, action = DENIALS[scenario]
    producer = "SilmarilHookRuntime" if managed else "VSCodeFirewallPlugin"
    expected = hashlib.sha256((prompt if managed else marker).encode()).hexdigest()
    eligible = [e for e in events if e.get("schemaVersion") == 1 and e.get("host") == "vscode"
                and e.get("mode") == "block" and e.get("provenance", {}).get("producer") == producer
                and e.get("provenance", {}).get("pluginVersion") == version]
    sessions = {e["sessionFingerprint"] for e in eligible if e.get("sessionFingerprint")
                and e.get("hook") == "user_input" and e.get("requestFingerprint") == expected}
    rows = [e for e in eligible if e.get("sessionFingerprint") in sessions and e.get("hook") == boundary
            and (boundary == "user_input" or read_tool(e))]
    if len(sessions) != 1 or not rows:
        return None
    blocked = [e for e in rows if e.get("policyDecision") == "block"]
    if not blocked:
        return "BLOCKED"
    if not all(e.get("nativeAction") == action for e in blocked):
        return "FAIL"
    messages = [r["data"].get("content") for r in history if r["type"] == "assistant.message"
                and not r["data"].get("toolRequests") and isinstance(r["data"].get("content"), str)]
    if not messages:
        return None
    response = messages[-1]
    if word in response:
        return "FAIL"
    if scenario == "prompt_denial":
        # The shared hook replaces the submitted prompt. The signed client's ordinary user
        # message must record that replacement without issuing the requested file read.
        if any(r["type"] == "tool.execution_start" for r in history):
            return "FAIL"
        replaced = any(r["type"] == "user.message" and r["data"].get("content") == BLOCK_MESSAGE for r in history)
        return "PASS" if replaced else None
    # The installed hook and the client must both report the standard denial. The
    # benign prompt asks the model to quote the reason but never supplies that wording.
    return "PASS" if BLOCK_MESSAGE in response else None


def run_case(scenario, workspace, profile, copilot, spool_dirs, pattern, submit, managed, version):
    marker = "silmaril-runtime-check:" + secrets.token_hex(16)
    filename = f"qa-{scenario}-{secrets.token_hex(10)}.txt"
    note = workspace / filename
    word = secrets.token_hex(16)
    name = scenario.replace("_", "-")
    prompt_tag = " RELEASE-QA-PROMPT-DENY." if scenario == "prompt_denial" else ""
    if scenario == "pre_tool_denial":
        note = workspace / ("RELEASE-QA-READ-DENY-" + filename)
    content = ("RELEASE-QA-RESULT-DENY " if scenario == "post_tool_denial" else "") + word
    prompt = (f"{marker}.{prompt_tag} Read the note {note.name} using the read tool. "
              "Reply with its contents. If the read is denied or the result is replaced, "
              "stop and quote the displayed reason verbatim.")
    previous = {p for spool in spool_dirs for p in spool.glob(pattern)}
    offsets = {p: p.stat().st_size for p in (copilot / "session-state").glob("*/events.jsonl")
               if p.is_file() and p.resolve() == p}
    with note.open("x", opener=lambda filename, flags: os.open(filename, flags, 0o600)) as f:
        f.write(content + "\n")
    try:
        since = time.time() * 1000
        submit(prompt)
        deadline = time.monotonic() + 210
        routed = None
        allowed = False
        while time.monotonic() < deadline:
            evidence = [read_json(p) for d in spool_dirs for p in d.glob(pattern)
                        if p not in previous and p.is_file() and p.resolve() == p]
            routed = renderer_state(profile, since)
            if routed:
                history = session_history(copilot, routed, offsets)
                if scenario == "allow":
                    allowed = valid_evidence(evidence, prompt=prompt, marker=marker, version=version, managed=managed)
                    # Verify final customer-visible readback against a value absent from the prompt.
                    if allowed and any(r["type"] == "assistant.message" and not r["data"].get("toolRequests")
                                       and word in str(r["data"].get("content", "")) for r in history):
                        return "PASS"
                else:
                    result = denial_observed(evidence, history, scenario=scenario, prompt=prompt, marker=marker,
                                             version=version, managed=managed, word=word)
                    if result in ("PASS", "FAIL"):
                        return result
                    if result == "BLOCKED" and history:
                        raise PhysicalHostUnavailable(f"{name}: Test Tenant did not supply the controlled policy denial")
            time.sleep(1)
        if routed and scenario == "allow" and not allowed:
            raise ValueError("Signed editor completed but its plugin did not observe the permitted read")
        raise PhysicalHostUnavailable(f"{name}: shared turn, signed-client reply or required native effect unobserved")
    finally:
        note.unlink(missing_ok=True)


def run_editor_checks(home, plugin, managed, version):
    checks = dict.fromkeys(("install", "native", "live", "policy_denial", *DENIALS), "BLOCKED")
    try:
        journey(home, plugin, managed, version, checks)
    except PhysicalHostUnavailable as exc:
        print(str(exc), file=sys.stderr)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        print(f"Editor acceptance failed ({type(exc).__name__})", file=sys.stderr)
        checks["native"] = "FAIL"
    return checks
