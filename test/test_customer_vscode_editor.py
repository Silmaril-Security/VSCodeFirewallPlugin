from contextlib import redirect_stderr
import hashlib
import io
import subprocess
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import customer_vscode_editor as driver


class EditorObservationTests(unittest.TestCase):

    def test_qa_hook_launcher_is_exact_and_scoped_to_the_editor_lifetime(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            account, run = root / "account", root / "run"
            account.mkdir()
            for managed, path, mode in (
                (False, ".vscode/silmaril-firewall-node-path", 0o600),
                (True, "Library/Application Support/Silmaril/Runtime/vscode/SilmarilHookRuntime", 0o755),
            ):
                source, target = run / path, account / path
                source.parent.mkdir(parents=True)
                source.write_bytes(b"verified payload")
                source.chmod(mode)
                with self.assertRaisesRegex(RuntimeError, "turn failed"):
                    with driver.installed_hook_launcher(account, run, managed):
                        self.assertEqual(target.read_bytes(), source.read_bytes())
                        self.assertEqual(target.stat().st_mode & 0o777, mode)
                        raise RuntimeError("turn failed")
                self.assertFalse(target.parent.exists())
                target.parent.mkdir(parents=True)
                target.write_bytes(source.read_bytes())
                target.chmod(mode)
                with driver.installed_hook_launcher(account, run, managed):
                    pass
                self.assertTrue(target.exists())
                target.write_bytes(b"preexisting installation")
                with self.assertRaises(driver.PhysicalHostUnavailable):
                    with driver.installed_hook_launcher(account, run, managed):
                        self.fail("conflicting installation was admitted")
                self.assertEqual(target.read_bytes(), b"preexisting installation")

    def test_standalone_computer_name_cache_restored_after_a_hook_refresh(self):
        with tempfile.TemporaryDirectory() as temp:
            account = Path(temp).resolve()
            cache = account / "Library/Application Support/Silmaril/ComputerName/cache.json"
            with driver.standalone_name_cache(account):
                cache.write_text("new cache")
            self.assertFalse((account / "Library").exists())
            cache.parent.mkdir(parents=True)
            cache.write_text("prior cache")
            original = cache.stat()
            with self.assertRaisesRegex(RuntimeError, "failed"):
                with driver.standalone_name_cache(account):
                    updated = cache.with_suffix(".tmp")
                    updated.write_text("refreshed cache")
                    updated.replace(cache)
                    raise RuntimeError("failed")
            self.assertEqual(cache.read_text(), "prior cache")
            self.assertEqual(cache.stat().st_ino, original.st_ino)
            self.assertEqual(list(cache.parent.iterdir()), [cache])

    def test_ingested_runtime_receipt_survives_spool_cleanup_and_preserves_event_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            incoming, receipts = root / "incoming", root / "receipts"
            incoming.mkdir()
            receipts.mkdir()
            event = {"id": "runtime:test", "hook": "pre_tool"}
            raw = incoming / "runtime-test.json"
            raw.write_text(json.dumps(event))
            receipt = {"event": event, "provenance": {"producer": "SilmarilMacOS"}, "schemaVersion": 1}
            path = receipts / (hashlib.sha256(event["id"].encode()).hexdigest() + ".json")
            path.write_text(json.dumps(receipt))
            (receipts / "unrelated.json").write_text(json.dumps(receipt))
            observed = list(driver.evidence_files([incoming], "runtime-*.json", True))
            raw.unlink()
            self.assertEqual(driver.fresh_events(observed, set()), [event])
            self.assertEqual(driver.fresh_events(observed, {path}), [])
            self.assertEqual(list(driver.evidence_files([incoming], "event-*.json", False)), [])

    def test_managed_shadow_blocks_only_the_correlated_turn(self):
        prompt = "unique QA read"
        event = {"schemaVersion": 1, "host": "vscode", "hook": "user_input", "mode": "shadow",
                 "provenance": {"pluginVersion": "0.3.1", "producer": "SilmarilHookRuntime"},
                 "requestFingerprint": hashlib.sha256(prompt.encode()).hexdigest(), "sessionFingerprint": "fresh"}
        args = dict(marker="marker", version="0.3.1", managed=True)
        self.assertFalse(driver.valid_evidence([event], prompt="unrelated", **args))
        with self.assertRaisesRegex(driver.PhysicalHostUnavailable, "shadow mode"):
            driver.valid_evidence([event], prompt=prompt, **args)

    def test_private_files_are_owner_only_and_never_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "settings.json"
            with driver.create_private_file(path) as stream:
                stream.write("first")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                driver.create_private_file(path)
            self.assertEqual(path.read_text(), "first")

    def test_editor_command_failure_reports_only_the_known_operation(self):
        for executable, label in (("/usr/bin/codesign", "editor signature verification"),
                                  ("/private/qa/secret-path", "editor command")):
            with self.subTest(executable=executable):
                failure = subprocess.CalledProcessError(1, [executable, "private-argument"],
                                                       stderr=b"private diagnostic")
                log = io.StringIO()
                with patch.object(driver, "journey", side_effect=failure), redirect_stderr(log):
                    checks = driver.run_editor_checks(None, None, True, "0.2.4")
                self.assertEqual(checks["native"], "FAIL")
                self.assertEqual(checks["live"], "BLOCKED")
                self.assertEqual(log.getvalue(), f"Editor acceptance failed during {label} (exit 1)\n")

    def test_workbench_turn_requires_its_own_sdk_mapping(self):
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp).resolve()
            renderer = profile / "logs/launch/window1/renderer.log"
            renderer.parent.mkdir(parents=True)
            row = {"interactionKind": "turn", "sessionType": driver.ROUTE,
                   "chatSessionId": driver.ROUTE + ":/workbench-id", "epochMs": 100}
            renderer.write_text("[ChatTTFP] end " + json.dumps(row))
            agent = renderer.parent.parent / "agenthost.log"
            sdk = "12345678-1234-1234-1234-123456789abc"
            line = (f"2026-11-22 13:55:19.279 [info] [Copilot:{sdk}] Preparing SDK session: "
                    "kind=create, configuration=ahp-session:/workbench-id, chat=ahp-chat:/chat-id")
            agent.write_text(line.replace("workbench-id", "other-workbench-id"))
            self.assertIsNone(driver.renderer_state(profile, 50))
            agent.write_text(line)
            self.assertEqual(driver.renderer_state(profile, 50), sdk)
            agent.write_text(line + "\n" + line.replace(sdk, "abcdef12" + sdk[8:]))
            with self.assertRaisesRegex(ValueError, "Ambiguous"):
                driver.renderer_state(profile, 50)

    def test_managed_prompt_uses_the_native_transform_for_the_exact_submitted_turn(self):
        event = {"sessionFingerprint": hashlib.sha256(b"sdk-id").hexdigest()}
        hook = {"sessionId": "sdk-id", "prompt": "original", "transformedPrompt": "native context and original"}
        history = [{"type": "hook.start", "data": {"hookType": "userPromptTransformed", "input": hook}}]
        self.assertEqual(driver.managed_turn_evidence([{}, event], history, "sdk-id", "original"),
                         ([event], "native context and original"))
        self.assertEqual(driver.managed_turn_evidence([event], history, "other-session", "original")[0], [])
        self.assertEqual(driver.managed_turn_evidence([event], history, "sdk-id", "other prompt")[0], [])

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

    def test_permission_denied_group_must_be_gone_or_entirely_defunct(self):
        proc = Mock(pid=12345)
        rows = b"12345 Z+\n6789 S\n"
        for responses in ([PermissionError()], [None, PermissionError()]):
            with patch.object(driver.os, "killpg", side_effect=responses), \
                 patch.object(driver, "run", return_value=Mock(stdout=rows)):
                driver.stop_editor_group(proc)
        self.assertEqual(proc.wait.call_count, 2)

    def test_permission_denied_live_helper_still_fails_cleanup(self):
        proc = Mock(pid=12345)
        rows = b"12345 Z\n12345 S\n"
        with patch.object(driver.os, "killpg", side_effect=PermissionError()), \
             patch.object(driver, "run", return_value=Mock(stdout=rows)):
            with self.assertRaisesRegex(OSError, "remained after group termination"):
                driver.stop_editor_group(proc, term_timeout=0, kill_timeout=0)
        proc.wait.assert_not_called()

    def test_blocked_editor_turn_cleans_up_each_signed_app_launch(self):
        with tempfile.TemporaryDirectory() as temp:
            profile = Path(temp)
            renderer = profile / "logs" / "today" / "window1" / "renderer.log"
            renderer.parent.mkdir(parents=True)
            renderer.write_text("Started local extension host with pid 123")
            editor, first_chat, second_chat = Mock(), Mock(), Mock()
            editor.poll.return_value = None
            with patch.object(subprocess, "Popen", side_effect=[editor, first_chat, second_chat]) as popen, \
                 patch.object(driver, "stop_editor_group") as stop:
                with self.assertRaises(driver.PhysicalHostUnavailable):
                    with driver.launch("/signed/Code", profile, profile, {"HOME": temp}) as submit:
                        submit("first")
                        submit("second")
                        raise driver.PhysicalHostUnavailable("no signed reply")
            self.assertEqual([call.args[0] for call in stop.call_args_list], [second_chat, first_chat, editor])
            for call, prompt in zip(popen.call_args_list[1:], ["first", "second"]):
                self.assertEqual(call.args[0], ["/signed/Code", "chat", "--reuse-window", "--mode", "agent", prompt])
                self.assertTrue(call.kwargs["start_new_session"])
                self.assertEqual(call.kwargs["env"]["HOME"], temp)
                self.assertEqual(call.kwargs["env"]["VSCODE_CLI"], "1")

    def test_chat_failure_during_observation_is_reported_and_note_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp)
            chat = Mock()
            chat.poll.side_effect = [None, 19]
            with patch.object(driver.time, "sleep"), self.assertRaisesRegex(ValueError, "exited with status 19"):
                driver.run_case("allow", workspace, workspace, workspace, [], "*.json",
                                lambda prompt: chat, True, "0.3.1")
            self.assertEqual(list(workspace.iterdir()), [])

    def test_socket_budget_is_validated_before_launch(self):
        profile = Path("/private/tmp") / ("x" * 100)
        with self.assertRaisesRegex(driver.PhysicalHostUnavailable, "socket path"):
            with driver.launch(None, profile, None, {}):
                self.fail("oversized socket should prevent launching the editor")
