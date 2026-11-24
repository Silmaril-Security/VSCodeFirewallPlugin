import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import customer_vscode_denials as denials
from customer_vscode_denials import Decisions
from macos_release_lease import PhysicalHostUnavailable


class ControlledDenials(unittest.TestCase):
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

    def test_unavailable_guest_reports_its_reason(self):
        stderr = b"Provision signed Microsoft VS Code 1.145.2 in /Applications\n"
        with self.assertRaisesRegex(
            PhysicalHostUnavailable,
            r"^Guest signed editor or QA login unavailable: Provision signed Microsoft VS Code 1\.145\.2 in /Applications$",
        ):
            self.published_denials(75, stderr)

    def test_failed_guest_reports_its_final_error_line(self):
        stderr = b"Traceback (most recent call last):\nValueError: Guest release payload differs from the staged artifact\n"
        with self.assertRaisesRegex(
            ValueError,
            r"^Guest denial journey did not produce a complete receipt: ValueError: Guest release payload differs",
        ):
            self.published_denials(1, stderr)
