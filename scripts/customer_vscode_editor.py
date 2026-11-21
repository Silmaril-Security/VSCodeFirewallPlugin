"""Run one ordinary Read through the signed editor and the installed firewall adapter."""
import contextlib
import hashlib
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
        return False
    row, path = rows[0]
    if row.get("sessionType") != ROUTE or not str(row.get("chatSessionId", "")).startswith(ROUTE + ":/"):
        raise ValueError("Chat executed in the wrong VS Code session type")
    return path in resources


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
    reads = {e.get("hook") for e in matching if "read" in (e.get("toolDisplayName") or "").lower()}
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
    marker = "silmaril-runtime-check:" + secrets.token_hex(16)
    note = workspace / ("qa-read-" + secrets.token_hex(10) + ".txt")
    prompt = f"{marker}. Use the read tool to read {note.name}. Reply with the word it contains."
    spool_dirs = {home / EVIDENCE}
    if managed:
        # Foundation may resolve Application Support from the standard QA login instead of HOME.
        spool_dirs.add(account_home / EVIDENCE)
    pattern = "runtime-*.json" if managed else "event-*.json"
    baseline = {p for spool in spool_dirs for p in spool.glob(pattern)}
    with note.open("x", opener=lambda name, flags: os.open(name, flags, 0o600)) as f:
        f.write("sunflower\n")
    try:
        with launch(binary, cli, profile, workspace, env) as submit:
            since = time.time() * 1000
            submit(prompt)
            deadline = time.monotonic() + 210
            while time.monotonic() < deadline:
                observed = []
                for directory in spool_dirs:
                    for path in directory.glob(pattern):
                        if path not in baseline and path.is_file() and path.resolve() == path:
                            observed.append(read_json(path))
                routed = renderer_state(profile, since)
                allowed = valid_evidence(observed, prompt=prompt, marker=marker, version=version, managed=managed)
                if allowed:
                    checks["install"] = "PASS"
                    checks["live"] = "PASS"
                if routed and allowed:
                    checks["native"] = "PASS"
                    return
                time.sleep(1)
            if routed:
                raise ValueError("Signed editor completed but the installed plugin did not classify all three Read boundaries")
            raise PhysicalHostUnavailable("No completed shared editor turn. Check the QA model entitlement, session selection and normal workspace trust")
    finally:
        note.unlink(missing_ok=True)


def run_editor_checks(home, plugin, managed, version):
    checks = dict.fromkeys(("install", "native", "live"), "BLOCKED")
    try:
        journey(home, plugin, managed, version, checks)
    except PhysicalHostUnavailable as exc:
        print(str(exc), file=sys.stderr)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        print(f"Editor acceptance failed ({type(exc).__name__})", file=sys.stderr)
        checks["native"] = "FAIL"
    return checks
