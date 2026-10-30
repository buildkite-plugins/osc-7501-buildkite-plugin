import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("report", ROOT / "lib/report.py")
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


def osc(body, terminator=b"\x1b\\"):
    return b"\x1b]7501;" + body + terminator


class ReportTests(unittest.TestCase):
    def test_real_agent_synthetic_captures(self):
        for scenario, count, final_state in [("failed", 13, "error"), ("successful", 13, "done"),
                                              ("blocked", 15, "done"), ("experiment-off", 0, None)]:
            with self.subTest(scenario=scenario):
                data = (ROOT / "tests/fixtures" / (scenario + ".raw")).read_bytes()
                result = report.extract(data, True)
                events = result["events"]
                self.assertEqual(len(events), count)
                self.assertEqual(result["source"]["limited"], [])
                if not events:
                    self.assertEqual(result["source"]["event_support"], "unknown")
                    self.assertIn("not evidence of success", report.render(result))
                    continue
                self.assertEqual([e["state"] for e in events if e["id"] == "command"][-1], final_state)
                self.assertEqual([e["progress"] for e in events if "progress" in e][:2], [40, 60])
                self.assertTrue(any(e["id"] == "hook/agent/pre-command" and e["state"] == "done" for e in events))
                self.assertEqual([e["state"] for e in events][-2:], ["clear", "clear"])
                self.assertIn("Compiling", next(e["details"] for e in events if e.get("details")))
                self.assertNotIn("details", events[0])  # Hidden lifecycle report.
                self.assertNotIn("details", next(e for e in events if e.get("progress") == 60))
                if scenario == "blocked":
                    self.assertTrue(any(e.get("kind") == "permission" and e["state"] == "blocked" for e in events))

    def test_safe_details_not_raw_payload_or_unrelated_text(self):
        secret = b"SYNTHETIC_SECRET_ONLY"
        encoded = base64.b64encode(secret)
        data = osc(b"state=working:id=build:msg=" + encoded)
        data += b'\x1b[90m# Program status: state=working id=build msg="[REDACTED] <script>alert(1)</script>"\x1b[0m\n'
        data += b"unrelated secret " + secret + b"\n"
        data += osc(b"state=done:id=build:msg=" + encoded)
        data += b'# Program status: state=done id=other msg="WRONG DETAIL"\n'
        for newline in (b"\n", b"\r\n"):
            for gap in (b"", newline, newline + b"\x1b_bk;t=1793315983242\x07"):
                wire = data.replace(b"\n", newline).replace(b"\x1b\\", b"\x1b\\" + gap, 1)
                result = report.extract(wire, True)
                self.assertEqual(result["events"][0].get("details"),
                                 'msg="[REDACTED] <script>alert(1)</script>"')
        for gap in (b"\n\n", b"\r\n\n", b"\nUNRELATED\n", b"\x1b_bk;t=notdigits\x07"):
            rejected = report.extract(data.replace(b"\x1b\\", b"\x1b\\" + gap, 1), True)
            self.assertNotIn("details", rejected["events"][0])
        with tempfile.TemporaryDirectory() as directory:
            report.write_report(result, directory)
            encoded_files = b"".join(p.read_bytes() for p in Path(directory).iterdir())
        self.assertNotIn(secret, encoded_files)
        self.assertNotIn(encoded, encoded_files)
        self.assertNotIn(b"WRONG DETAIL", encoded_files)
        self.assertIn(b"[REDACTED]", encoded_files)
        page = report.render(result)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("details", report.extract(data)["events"][0])
        self.assertNotIn("details", result["events"][1])

    def test_framing_and_limits(self):
        valid = osc(b"state=done:id=ok", b"\x07")
        data = osc(b'state=working:id=bad:msg=AAAA\n# Program status: state=done id=ok msg="LEAK"') + valid
        result = report.extract(data, True)
        self.assertEqual([e["id"] for e in result["events"]], ["ok"])
        self.assertEqual(result["events"][0]["snapshot_line"], 2)
        self.assertNotIn("LEAK", json.dumps(result))
        cases = [osc(b"state=done:id=" + b"a" * 5000), osc(b"state=bad:id=x"),
                 osc(b"state=done:id=a//b"), osc(b"state=done:" + b"x=a:" * 25),
                 b"\x1b]7501;state=done:id=unfinished"]
        for bad in cases:
            with self.subTest(bad=bad[:50]):
                result = report.extract(bad)
                self.assertEqual(result["events"], [])
                self.assertTrue(result["source"]["limited"])
        result = report.extract(valid * 1001)
        self.assertEqual(len(result["events"]), 1000)
        self.assertIn("event count limit", result["source"]["limited"])
        result = report.extract(b"a" * (report.MAX_LOG + 1) + valid)
        self.assertEqual(result["events"], [])
        self.assertIn("log byte limit", result["source"]["limited"])

    def test_clear_replacement_repeat_and_hierarchy(self):
        bodies = [b"state=working:id=command", b"state=working:id=build:progress=10",
                  b"state=working:id=build:progress=10", b"state=done:id=build/test",
                  b"state=clear:id=build", b"state=working:id=build:app=new"]
        result = report.extract(b"".join(osc(b) for b in bodies))
        self.assertEqual(len(result["events"]), 6)
        page = report.render(result)
        self.assertIn('test</code> <span class="state cleared">cleared', page)
        self.assertIn('build</code> <span class="state working">working', page)
        self.assertEqual(page.count('<tr id="event-'), 6)
        # command and build are sibling roots, not a fabricated parent/child pair.
        self.assertIn('command</p></details></li><li>', page)
        self.assertNotIn("progress", result["events"][-1])

    def test_invalid_duplicate_fields_cannot_clear_valid_errors(self):
        error = osc(b"state=error:id=build/test")
        for fields in (b"id=invalid//id:id=build", b"id=:id=build",
                       b"id=build:app=" + b"a" * 33 + b":app=ok"):
            with self.subTest(fields=fields):
                result = report.extract(error + osc(b"state=clear:" + fields))
                self.assertEqual(len(result["events"]), 1)
                self.assertIn("unsupported or malformed OSC report", result["source"]["limited"])
                self.assertIn('test</code> <span class="state error">error', report.render(result))

    def test_serialized_size_bound_includes_html_escaping(self):
        payload = osc(b"state=working:id=x") + b'# Program status: state=working id=x msg="' + b"<&" * 900 + b'"\n'
        result = report.extract(payload * 1000, True)
        with tempfile.TemporaryDirectory() as directory:
            report.write_report(result, directory)
            for path in Path(directory).iterdir():
                self.assertLessEqual(path.stat().st_size, report.MAX_ARTIFACT)
            saved = json.loads((Path(directory) / "events.v1.json").read_text())
        self.assertIn("artifact size limit", saved["source"]["limited"])
        self.assertGreater(len(saved["events"]), 0)
        self.assertEqual([e["sequence"] for e in saved["events"]], list(range(1, len(saved["events"]) + 1)))

    def test_local_cli_writes_two_self_contained_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(["python3", "-I", str(ROOT / "lib/report.py"), "local",
                            str(ROOT / "tests/fixtures/failed.raw"), directory, "--include-details"], check=True)
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ["events.v1.json", "report.html"])
            self.assertEqual(json.loads((Path(directory) / "events.v1.json").read_text())["schema_version"], 1)
            page = (Path(directory) / "report.html").read_text()
            self.assertIn("default-src 'none'", page)
            self.assertNotIn("src=", page)


class LocalFileTests(unittest.TestCase):
    def test_bounded_regular_file_read_and_rejection_of_special_files(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "job.log"
            log.write_bytes(b"hello")
            self.assertEqual(report.read_snapshot(log), (b"hello", False))
            log.write_bytes(b"z" * (report.MAX_LOG + 100))
            data, limited = report.read_snapshot(log)
            self.assertEqual(data, b"z" * report.MAX_LOG)
            self.assertTrue(limited)
            log.write_bytes(b"")
            self.assertEqual(report.read_snapshot(log), (b"", False))
            fifo = Path(directory) / "fifo"
            os.mkfifo(fifo)
            link = Path(directory) / "link"
            link.symlink_to(log)
            started = time.monotonic()
            for path in (fifo, link, Path(directory), Path(directory) / "missing", Path("/dev/null")):
                with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                    report.read_snapshot(path)
            self.assertLess(time.monotonic() - started, 1)


class HookTests(unittest.TestCase):
    def test_hook_preserves_command_outcomes_when_log_or_upload_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            agent = Path(directory) / "buildkite-agent"
            agent.write_text('#!/bin/bash\nprintf "%s\\n" "$*" > "$CAPTURE/args"\ncp osc7501/* "$CAPTURE/"\nprintf "DO_NOT_LOG_AGENT_PAYLOAD" >&2\nexit "${UPLOAD_EXIT:-0}"\n')
            agent.chmod(0o755)
            env = {"PATH": directory + os.pathsep + os.defpath + ":/usr/local/bin", "CAPTURE": directory}
            for status in ("0", "7"):
                for upload_exit in ("0", "9"):
                    env["UPLOAD_EXIT"] = upload_exit
                    result = subprocess.run(["bash", "-c", 'bash -c "exit $1"; export BUILDKITE_COMMAND_EXIT_STATUS=$?; "$2"; hook_status=$?; test "$hook_status" = 0 || exit 99; exit "$BUILDKITE_COMMAND_EXIT_STATUS"',
                                             "test", status, str(ROOT / "hooks/post-command")], env=env, capture_output=True)
                    self.assertEqual(result.returncode, int(status))
                    self.assertIn(b"log snapshot unavailable", result.stdout)
                    self.assertNotIn(b"DO_NOT_LOG_AGENT_PAYLOAD", result.stdout + result.stderr)
                    self.assertEqual((Path(directory) / "args").read_text().strip(), "artifact upload osc7501/*")
                    saved = json.loads((Path(directory) / "events.v1.json").read_text())
                    self.assertEqual(saved["source"]["availability"], "unavailable")
                    if upload_exit != "0":
                        self.assertIn(b"artifact upload unavailable", result.stdout)

    def test_local_file_to_artifact_upload_with_default_options(self):
        with tempfile.TemporaryDirectory() as directory:
            agent = Path(directory) / "buildkite-agent"
            agent.write_text('#!/bin/bash\nprintf "%s\\n" "$*" > "$CAPTURE/args"\ncp osc7501/* "$CAPTURE/"\n')
            agent.chmod(0o755)
            env = {"PATH": directory + os.pathsep + os.defpath + ":/usr/local/bin", "CAPTURE": directory}
            for scenario, count, status in (("failed", 13, 7), ("successful", 13, 0),
                                            ("blocked", 15, 0), ("experiment-off", 0, 0)):
                with self.subTest(scenario=scenario):
                    env["BUILDKITE_JOB_LOG_TMPFILE"] = str(ROOT / "tests/fixtures" / (scenario + ".raw"))
                    # Run an actual command, then the optional hook, preserving its result.
                    result = subprocess.run(["bash", "-c", 'bash -c "exit $1"; export BUILDKITE_COMMAND_EXIT_STATUS=$?; "$2"; exit "$BUILDKITE_COMMAND_EXIT_STATUS"',
                                             "test", str(status), str(ROOT / "hooks/post-command")], env=env, capture_output=True)
                    self.assertEqual(result.returncode, status)
                    self.assertEqual(result.stdout + result.stderr, b"")
                    saved = json.loads((Path(directory) / "events.v1.json").read_text())
                    self.assertEqual(saved["source"]["availability"], "available")
                    self.assertEqual(len(saved["events"]), count)
                    self.assertEqual((Path(directory) / "args").read_text().strip(), "artifact upload osc7501/*")
                    self.assertTrue(all("details" not in e for e in saved["events"]))
                    if count:
                        self.assertEqual([e["state"] for e in saved["events"]][-2:], ["clear", "clear"])
                    else:
                        self.assertEqual(saved["source"]["event_support"], "unknown")
            env[report.PREFIX + "INCLUDE_DETAILS"] = "true"
            env["BUILDKITE_JOB_LOG_TMPFILE"] = str(ROOT / "tests/fixtures/failed.raw")
            subprocess.run([str(ROOT / "hooks/post-command")], env=env, check=True)
            saved = json.loads((Path(directory) / "events.v1.json").read_text())
            self.assertEqual(len(saved["events"]), 13)
            self.assertIn("Compiling", next(e["details"] for e in saved["events"] if "details" in e))

    def test_parse_failure_and_upload_timeout_are_fail_open(self):
        with tempfile.TemporaryDirectory() as directory:
            agent = Path(directory) / "buildkite-agent"
            agent.write_text('#!/bin/bash\ncp osc7501/* "$CAPTURE/"\n')
            agent.chmod(0o755)
            env = {"PATH": directory + os.pathsep + os.defpath, "CAPTURE": directory,
                   "BUILDKITE_JOB_LOG_TMPFILE": str(ROOT / "tests/fixtures/failed.raw")}
            for status in ("0", "7"):
                env["BUILDKITE_COMMAND_EXIT_STATUS"] = status
                with patch.dict(os.environ, env, clear=True):
                    report.hook()
                    saved = json.loads((Path(directory) / "events.v1.json").read_text())
                    self.assertEqual(saved["source"]["availability"], "available")
                    self.assertEqual(len(saved["events"]), 13)
                    with patch.object(report, "extract", side_effect=ValueError("SYNTHETIC_CREDENTIAL")):
                        with contextlib.redirect_stdout(io.StringIO()) as output:
                            report.hook()
                        self.assertIn("log snapshot unavailable", output.getvalue())
                        self.assertNotIn("SYNTHETIC_CREDENTIAL", output.getvalue())
                        saved = json.loads((Path(directory) / "events.v1.json").read_text())
                        self.assertEqual(saved["source"]["availability"], "unavailable")
                    with patch.object(report.subprocess, "run", side_effect=subprocess.TimeoutExpired("agent", 15)):
                        with contextlib.redirect_stdout(io.StringIO()) as output:
                            report.hook()
                        self.assertIn("artifact upload unavailable", output.getvalue())
                    self.assertEqual(os.environ["BUILDKITE_COMMAND_EXIT_STATUS"], status)


if __name__ == "__main__":
    unittest.main()
