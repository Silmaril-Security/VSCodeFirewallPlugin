import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from customer_vscode_denials import Decisions


class ControlledDenials(unittest.TestCase):
    def test_only_the_armed_boundary_and_marker_produce_a_deny(self):
        for scenario, hook in (("prompt_denial", "USER_INPUT"), ("pre_tool_denial", "TOOL_CALL"),
                               ("post_tool_denial", "TOOL_RESPONSE")):
            with self.subTest(scenario=scenario):
                decisions = Decisions()
                decisions.arm(scenario, "unique-file")
                payload = {"text": "Read unique-file", "metadata": {"conversationId": "signed-session"},
                           "hook": hook}
                for changed in ({"text": "another file"}, {"hook": "OTHER"}, {"metadata": {}}):
                    self.assertEqual(decisions.classify({**payload, **changed})["prediction"], "BENIGN")
                self.assertFalse(decisions.denied("signed-session"))
                self.assertEqual(decisions.classify(payload, v2=True)["results"][0]["action"], "block")
                self.assertTrue(decisions.denied("signed-session"))
                self.assertFalse(decisions.denied("another-session"))
                decisions.arm("allow", "unique-file")
                self.assertFalse(decisions.denied("signed-session"))
                self.assertEqual(decisions.classify(payload)["prediction"], "BENIGN")
