"""Run the published editor's denial journeys in the Atlanta QA guest."""
import contextlib
import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading

from macos_release_lease import PhysicalHostUnavailable


LAB = Path("/Users/Shared/silmaril-release-qa/vscode-denial-lab")
GUEST = "vscode-denial-lab"
SHARE = Path("/Volumes/My Shared Files/input")
RUNTIME = Path("Library/Application Support/Silmaril/Runtime/vscode/SilmarilHookRuntime")
PLUGIN = Path(".vscode/silmaril-firewall")
NODE = Path(".vscode/silmaril-firewall-node-path")
BOUNDARIES = {"prompt_denial": "user_input", "pre_tool_denial": "tool_call", "post_tool_denial": "tool_response"}


class Decisions:
    """Retain only the callback identity for a deny issued in this run."""
    def __init__(self):
        self.key = secrets.token_hex(32)
        self.hook = self.marker = None
        self.sessions = set()
        self.lock = threading.Lock()

    def arm(self, scenario, marker):
        with self.lock:
            self.hook = BOUNDARIES.get(scenario)
            self.marker = marker
            self.sessions.clear()

    def classify(self, payload, *, v2=False):
        hook, text = payload.get("hook"), payload.get("text")
        metadata = payload.get("metadata", {})
        session = metadata.get("conversationId")
        tool = str(payload.get("tool_name", "")).lower().replace("_", "").replace(" ", "")
        with self.lock:
            deny = (self.hook is not None and isinstance(hook, str) and self.hook == hook.lower() and isinstance(text, str)
                    and (self.hook == "user_input" or tool in {"read", "readfile", "view"})
                    and self.marker in text and isinstance(session, str) and bool(session))
            if deny:
                self.sessions.add(session)
        if v2:
            return {"results": [{"action": "block" if deny else "allow", "source": "model"}]}
        return {"prediction": "MALICIOUS" if deny else "BENIGN",
                "score": 0.99 if deny else 0.01, "threshold": 0.5}

    def denied(self, session):
        with self.lock:
            return session in self.sessions


@contextlib.contextmanager
def classifier():
    fixture = Decisions()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            if self.path not in ("/classify", "/v2/classify"):
                return self.send_error(404)
            if not hmac.compare_digest(self.headers.get("x-api-key", "").encode(), fixture.key.encode()):
                return self.send_error(403)
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 2**20:
                    return self.send_error(413)
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict) or not isinstance(payload.get("metadata"), dict):
                    return self.send_error(400)
                body = json.dumps(fixture.classify(payload, v2=self.path == "/v2/classify")).encode()
            except (ValueError, UnicodeError):
                return self.send_error(400)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(LAB / "localhost.crt", LAB / "localhost.key")
    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield fixture, f"https://127.0.0.1:{server.server_port}/classify"
        finally:
            server.shutdown()
            thread.join()


def fingerprint(root):
    result = {}
    for p in sorted(root.rglob("*")):
        if p.is_symlink():
            raise ValueError("Unexpected symlink in denial payload")
        if p.is_file():
            result[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return result


def configure_guest_node(home):
    # The standalone launcher requires a private locator and a root- or QA-owned Node.
    user_node = Path.home() / ".local/bin/node"
    node = user_node if user_node.is_file() else shutil.which("node")
    if not node:
        raise PhysicalHostUnavailable("The guest requires Node.js for the standalone payload")
    locator = home / NODE
    locator.chmod(0o600)
    locator.write_text(str(Path(node).resolve(strict=True)) + "\n")


def guest():
    from customer_vscode_editor import journey
    if not subprocess.check_output(["/usr/sbin/sysctl", "-n", "hw.model"]).startswith(b"Virtual"):
        raise ValueError("Controlled decisions require a QA virtual machine")
    spec = json.loads((SHARE / "input.json").read_bytes())
    managed = spec["managed"]
    with tempfile.TemporaryDirectory(dir="/private/tmp", prefix="sv-") as tmp:
        home = Path(tmp).resolve() / "home"
        shutil.copytree(SHARE / "payload", home)
        if fingerprint(home) != spec["files"]:
            raise ValueError("Guest release payload differs from the staged artifact")
        if not managed:
            configure_guest_node(home)
        with classifier() as (fixture, url):
            checks = {}
            journey(home, home / PLUGIN, managed, spec["version"], checks,
                    controlled=(fixture, url, LAB / "localhost.crt"))
            if checks.get("native") != "PASS":
                raise PhysicalHostUnavailable("Guest signed-editor allow control did not pass")
            print(json.dumps({"run": spec["run"], "checks": {k: checks[k] for k in BOUNDARIES}}))


def published_denials(home, managed, version):
    """Share only verified release files and the driver, under the existing physical lease."""
    tart = LAB / "Tart.app/Contents/MacOS/tart"
    if not tart.is_file():
        raise PhysicalHostUnavailable("Provision the Atlanta VS Code denial guest")
    # The running guest mounts only this QA-owned inbox read-only. The physical lease serializes jobs.
    with tempfile.TemporaryDirectory(dir=LAB / "inbox", prefix="run-") as stage:
        stage = Path(stage)
        payload = stage / "payload"
        shutil.copytree(home / PLUGIN, payload / PLUGIN)
        other = RUNTIME if managed else NODE
        (payload / other).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(home / other, payload / other)
        scripts = Path(__file__).resolve().parent
        for name in ("customer_vscode_denials.py", "customer_vscode_editor.py", "macos_release_lease.py"):
            shutil.copy2(scripts / name, stage / name)
        spec = {"managed": managed, "version": version, "run": secrets.token_hex(16), "files": fingerprint(payload)}
        (stage / "input.json").write_text(json.dumps(spec))
        env = {"PATH": "/usr/bin:/bin", "HOME": os.path.expanduser("~"), "TART_HOME": str(LAB / "guest-state"),
               "TART_NO_TELEMETRY": "1", "TART_NO_AUTO_PRUNE": "1"}
        exe = str(SHARE / stage.name / "customer_vscode_denials.py")
        # VirtioFS is read-only in the guest. Only release bytes and test code cross it.
        for entry in stage.rglob("*"):
            entry.chmod(0o755 if entry.is_dir() or entry.stat().st_mode & 0o111 else 0o644)
        stage.chmod(0o755)
        # Tart runs exec in the current console user's session. The guest validates its QA identity.
        result = subprocess.run([tart, "exec", GUEST, "/usr/bin/python3", exe],
                                capture_output=True, env=env, timeout=1100)
        if result.returncode:
            reason = result.stderr.decode(errors="replace").strip().splitlines()[-1:]
            detail = f": {reason[0][:300]}" if reason else ""
            if result.returncode == 75:
                raise PhysicalHostUnavailable("Guest signed editor or QA login unavailable" + detail)
            raise ValueError("Guest denial journey did not produce a complete receipt" + detail)
        receipt = json.loads(result.stdout)
        checks = receipt["checks"]
        if (receipt.get("run") != spec["run"] or set(checks) != set(BOUNDARIES)
                or any(v not in ("PASS", "FAIL", "BLOCKED") for v in checks.values())):
            raise ValueError("Invalid guest denial receipt")
        return checks


if __name__ == "__main__":
    SHARE = Path(__file__).resolve().parent
    try:
        guest()
    except PhysicalHostUnavailable as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(75)
