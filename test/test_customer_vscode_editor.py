import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import customer_vscode_editor as driver


class EditorObservationTests(unittest.TestCase):
    def test_rendered_route_and_fresh_time_are_required(self):
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp).resolve()
            log = profile / "logs/one/window1/renderer.log"
            log.parent.mkdir(parents=True)
            row = {"interactionKind": "turn", "sessionType": driver.ROUTE,
                   "chatSessionId": driver.ROUTE + ":/one", "epochMs": 100}
            log.write_text("[ChatTTFP] end " + json.dumps(row))
            self.assertFalse(driver.renderer_state(profile, 50))
            log.write_text(f"vscode-chat-session://{driver.ROUTE}/one\n[ChatTTFP] end " + json.dumps(row))
            self.assertTrue(driver.renderer_state(profile, 50))
            self.assertFalse(driver.renderer_state(profile, 101))

    def test_all_read_boundaries_require_same_session_and_exact_release(self):
        args = dict(prompt="one", marker="two", version="0.3.1", managed=True)
        common = {"schemaVersion": 1, "sessionFingerprint": "session", "host": "vscode", "mode": "block", "prediction": "benign",
                  "policyDecision": "allow", "nativeAction": "allowed", "provenance": {"pluginVersion": "0.3.1",
                  "producer": "SilmarilHookRuntime"}}
        event = {"hook": "user_input", "requestFingerprint": hashlib.sha256(b"one").hexdigest(), **common}
        pre = {"hook": "pre_tool", "toolDisplayName": "read_file", **common}
        post = {**pre, "hook": "tool_result"}
        self.assertTrue(driver.valid_evidence([event, pre, post], **args))
        self.assertFalse(driver.valid_evidence([event, post], **args))
        self.assertFalse(driver.valid_evidence([event, pre, {**post, "sessionFingerprint": "unrelated"}], **args))
        self.assertFalse(driver.valid_evidence([event, pre, post], **{**args, "version": "0.2.4"}))
        with self.assertRaises(ValueError):
            driver.valid_evidence([event, pre, {**post, "prediction": "malicious"}], **args)
