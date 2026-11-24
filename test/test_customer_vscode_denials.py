import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import customer_vscode_denials as denials
from customer_vscode_denials import Decisions, NODE, configure_guest_node
from macos_release_lease import PhysicalHostUnavailable


class ControlledDenials(unittest.TestCase):
    def test_guest_rewrites_shared_locator_with_private_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            account = Path(temp).resolve()
            node = account / ".local/bin/node"
            node.parent.mkdir(parents=True)
            node.touch(mode=0o755)
            run = account / "run"
            locator = run / NODE
            locator.parent.mkdir(parents=True)
            locator.write_text("/host/node\n")
            locator.chmod(0o644)
            with patch.object(Path, "home", return_value=account):
                configure_guest_node(run)
            self.assertEqual(locator.read_text(), f"{node}\n")
            self.assertEqual(locator.stat().st_mode & 0o777, 0o600)

    def test_only_the_armed_boundary_and_marker_produce_a_deny(self):
        for scenario, hook in (("prompt_denial", "USER_INPUT"), ("pre_tool_denial", "TOOL_CALL"),
                               ("post_tool_denial", "TOOL_RESPONSE")):
            with self.subTest(scenario=scenario):
                decisions = Decisions()
                decisions.arm(scenario, "unique-file")
                payload = {"text": "Read unique-file", "metadata": {"conversationId": "signed-session"},
                           "hook": hook, "tool_name": "view"}
                for changed in ({"text": "another file"}, {"hook": "OTHER"}, {"metadata": {}}):
                    self.assertEqual(decisions.classify({**payload, **changed})["prediction"], "BENIGN")
                self.assertFalse(decisions.denied("signed-session"))
                self.assertEqual(decisions.classify(payload, v2=True)["results"][0]["action"], "block")
                self.assertTrue(decisions.denied("signed-session"))
                self.assertFalse(decisions.denied("another-session"))
                decisions.arm("allow", "unique-file")
                self.assertFalse(decisions.denied("signed-session"))
                self.assertEqual(decisions.classify(payload)["prediction"], "BENIGN")


class GuestFailureReason(unittest.TestCase):
    def published_denials(self, returncode, stderr):
        with tempfile.TemporaryDirectory() as lab, tempfile.TemporaryDirectory() as home:
            lab, home = Path(lab), Path(home)
            tart = lab / "Tart.app/Contents/MacOS/tart"
            tart.parent.mkdir(parents=True)
            tart.touch()
            (lab / "inbox").mkdir()
            (home / denials.PLUGIN).mkdir(parents=True)
            (home / denials.NODE).write_text("/usr/bin/node\n")
            result = subprocess.CompletedProcess([], returncode, b"", stderr)
            with patch.object(denials, "LAB", lab), patch.object(denials.subprocess, "run", return_value=result):
                denials.published_denials(home, False, "0.3.2")

    def test_unavailable_guest_reports_its_prerequisite(self):
        stderr = b"Provision signed Microsoft VS Code 1.145.2 in /Applications or ~/Applications\n"
        with self.assertRaisesRegex(
            PhysicalHostUnavailable,
            r"^Guest prerequisite unavailable: Provision signed Microsoft VS Code 1\.145\.2 in /Applications or ~/Applications$",
        ):
            self.published_denials(75, stderr)

    def test_failed_guest_output_stays_out_of_the_error(self):
        stderr = b"Traceback (most recent call last):\nCalledProcessError: Command ['code', 'private prompt'] failed\n"
        with self.assertRaises(ValueError) as raised:
            self.published_denials(1, stderr)
        self.assertEqual(str(raised.exception), "Guest denial journey did not produce a complete receipt")
