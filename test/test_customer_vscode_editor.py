import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

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

    def test_denial_requires_product_action_and_matching_signed_client_outcome(self):
        prompt, nonce, word = "benign-policy-turn", "marker", "unprompted-word"
        args = dict(prompt=prompt, marker=nonce, version="0.3.1", managed=True, word=word)
        metadata = dict(schemaVersion=1, host="vscode", mode="block", sessionFingerprint="abc",
                        provenance=dict(producer="SilmarilHookRuntime", pluginVersion="0.3.1"))
        prompt_row = dict(**metadata, hook="user_input", requestFingerprint=hashlib.sha256(prompt.encode()).hexdigest())
        reply = {"type": "assistant.message", "data": {"content": driver.BLOCK_MESSAGE}}
        for name, (hook, action) in driver.DENIALS.items():
            expected = {**metadata, "hook": hook, "toolDisplayName": "read_file", "policyDecision": "block",
                        "nativeAction": action}
            transcript = [reply]
            if name == "prompt_denial":
                expected.update(requestFingerprint=prompt_row["requestFingerprint"])
                transcript = [{"type": "user.message", "data": {"content": driver.BLOCK_MESSAGE}}, reply]
            rows = [prompt_row, expected]
            self.assertEqual(driver.denial_observed(rows, transcript, scenario=name, **args), "PASS")
            self.assertIsNone(driver.denial_observed(rows, [], scenario=name, **args))
            leaked = [*transcript, {"type": "assistant.message", "data": {"content": word}}]
            self.assertEqual(driver.denial_observed(rows, leaked, scenario=name, **args), "FAIL")
            self.assertEqual(driver.denial_observed([prompt_row, {**expected, "policyDecision": "allow"}],
                                                    transcript, scenario=name, **args), "BLOCKED")


    def test_group_cleanup_kills_lingering_helpers_after_leader_exit(self):
        proc = Mock(pid=1111)
        proc.poll.return_value = 0
        calls = []
        def signal_group(pid, sig):
            self.assertEqual(pid, proc.pid)
            calls.append(sig)
            if sig == 0 and driver.signal.SIGKILL in calls:
                raise ProcessLookupError()
        with patch.object(driver.os, "killpg", side_effect=signal_group):
            driver.stop_editor_group(proc, term_timeout=0, kill_timeout=1)
        self.assertEqual(calls, [driver.signal.SIGTERM, 0, driver.signal.SIGKILL, 0])
        proc.wait.assert_called_once()

    def test_socket_budget_is_validated_before_launch(self):
        profile = Path("/private/tmp") / ("x" * 100)
        with self.assertRaisesRegex(driver.PhysicalHostUnavailable, "socket path"):
            with driver.launch(None, None, profile, None, {}):
                self.fail("oversized socket should prevent launching the editor")
