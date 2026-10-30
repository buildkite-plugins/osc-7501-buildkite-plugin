import base64
import contextlib
from html.parser import HTMLParser
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


AGENT_STAND_IN = '''#!/bin/bash
printf 'DO_NOT_LOG_AGENT_PAYLOAD' >&2
case "$1" in
  artifact)
    printf '%s\\n' "$*" > "$CAPTURE/upload-args"
    find osc7501 -type f > "$CAPTURE/uploaded-files"
    cp "$3" "$CAPTURE/"
    exit "${UPLOAD_EXIT:-0}"
    ;;
  annotate)
    printf '%s\\n' "$*" > "$CAPTURE/annotation-args"
    cat > "$CAPTURE/annotation.html"
    exit "${ANNOTATE_EXIT:-0}"
    ;;
  *) exit 99 ;;
esac
'''


def osc(body, terminator=b"\x1b\\"):
    return b"\x1b]7501;" + body + terminator


class HistoryRows(HTMLParser):
    def __init__(self, page):
        super().__init__()
        self.rows = []
        self.row = []
        self.cell = None
        self.feed(page)

    def handle_starttag(self, tag, attrs):
        if tag == "tr":
            self.row = []
        elif tag == "td":
            self.cell = []

    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag == "td":
            self.row.append(''.join(self.cell))
            self.cell = None
        elif tag == "tr" and self.row:
            self.rows.append(self.row)


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
        tree, history = page.split('<details><summary>Chronological history', 1)
        # Replacements discard live details, not the escaped historical record.
        self.assertNotIn("&lt;script&gt;", tree)
        self.assertIn("&lt;script&gt;", history)
        self.assertNotIn(secret.decode(), page)
        self.assertNotIn(encoded.decode(), page)
        self.assertNotIn("WRONG DETAIL", page)
        self.assertNotIn("<script>", page)
        self.assertIn('[REDACTED] <script>alert(1)</script>', HistoryRows(page).rows[0][3])
        self.assertEqual(HistoryRows(page).rows[1][3], 'Details unavailable')
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
        self.assertIn('test</code> <strong><span class="muted">cleared</span></strong> · 1 reports · last before clear: <span class="green">done</span>', page)
        self.assertIn('build</code> <strong><span class="blue">working</span></strong> · 4 reports · app=new', page)
        self.assertIn('6 chronological reports', page)
        # command and build are sibling roots, not a fabricated parent/child pair.
        self.assertIn('</details></li><li><details open><summary><code>build</code>', page)
        self.assertEqual(page.count('<details open>'), 3)
        self.assertIn('<details><summary>Chronological history (6 of 6 reports)</summary>', page)
        rows = HistoryRows(page).rows
        self.assertEqual([row[:3] for row in rows], [
            ['1', 'command', 'working'], ['2', 'build', 'working'], ['3', 'build', 'working'],
            ['4', 'build/test', 'done'], ['5', 'build', 'clear'], ['6', 'build', 'working']])
        self.assertTrue(rows[1][3].startswith('progress=10'))
        self.assertTrue(rows[2][3].startswith('progress=10'))
        self.assertEqual(rows[5][3], 'app=newDetails unavailable')
        self.assertNotIn("progress", result["events"][-1])

    def test_metadata_only_groups_show_their_own_recent_reports(self):
        bodies = [b"state=working:id=command", b"state=done:id=checkout",
                  b"state=working:id=command:progress=20", b"state=working:id=command:progress=40",
                  b"state=working:id=command:progress=60", b"state=working:id=command:progress=80",
                  b"state=error:id=command", b"state=error"]
        result = report.extract(b"\n".join(osc(b) for b in bodies))
        page = report.render(result)
        command = page.split('<code>command</code>', 1)[1].split('</details>', 1)[0]
        self.assertIn('Readable details unavailable', command)
        self.assertIn('Showing the last 5 of 6 reports', command)
        self.assertIn('Report #3 · <span class="blue">working</span> · progress=20 · snapshot line 3', command)
        self.assertIn('Report #7 · <span class="red">error</span> · snapshot line 7', command)
        self.assertEqual(command.count('<li>Report #'), 5)
        for sequence in (1, 2, 8):
            self.assertNotIn('Report #' + str(sequence) + ' ·', command)
        root = page.split('<code>(root record)</code>', 1)[1].split('</details>', 1)[0]
        self.assertIn('Report #8 · <span class="red">error</span> · snapshot line 8', root)
        self.assertEqual(len(result['events']), 8)
        self.assertEqual([int(row[0]) for row in HistoryRows(page).rows], list(range(1, 9)))

    def test_state_colours_preserve_labels_and_json(self):
        colours = [('error', 'red'), ('done', 'green'), ('blocked', 'orange'),
                   ('working', 'blue'), ('idle', 'muted'), ('clear', 'muted')]
        data = b'\n'.join(osc(('state=' + state + ':id=tools/' + state).encode())
                          for state, _ in colours)
        result = report.extract(data)
        original = json.dumps(result)
        page = report.render(result)
        tree, history = page.split('<details><summary>Chronological history', 1)
        self.assertIn('<code>tools</code> <strong>group</strong>', tree)
        for sequence, (state, colour) in enumerate(colours, 1):
            with self.subTest(state=state):
                label = '<span class="' + colour + '">' + state + '</span>'
                self.assertIn('<li>Report #' + str(sequence) + ' · ' + label, tree)
                self.assertIn('<td>' + label + '</td>', history)
                latest = '<span class="muted">cleared</span>' if state == 'clear' else label
                self.assertIn('<code>' + state + '</code> <strong>' + latest + '</strong>', tree)
        self.assertEqual([row[2] for row in HistoryRows(page).rows], [state for state, _ in colours])
        self.assertEqual(json.dumps(result), original)
        self.assertNotIn('<style', page)
        self.assertNotIn('style=', page)

    def test_group_with_no_visible_content_has_no_disclosure(self):
        bodies = [b'state=done:id=program' + str(i).encode() for i in range(99)]
        bodies.append(b'state=error:id=branch/leaf')
        result = report.extract(b''.join(osc(body) for body in bodies))
        page = report.render(result)
        self.assertIn('<li><code>branch</code> <strong>group</strong></li>', page)
        self.assertNotIn('<summary><code>branch</code>', page)
        self.assertNotIn('<ul></ul>', page)
        self.assertIn('Other programs are omitted', page)
        self.assertEqual(HistoryRows(page).rows[-1][1:3], ['branch/leaf', 'error'])

    def test_invalid_duplicate_fields_cannot_clear_valid_errors(self):
        error = osc(b"state=error:id=build/test")
        for fields in (b"id=invalid//id:id=build", b"id=:id=build",
                       b"id=build:app=" + b"a" * 33 + b":app=ok"):
            with self.subTest(fields=fields):
                result = report.extract(error + osc(b"state=clear:" + fields))
                self.assertEqual(len(result["events"]), 1)
                self.assertIn("unsupported or malformed OSC report", result["source"]["limited"])
                self.assertIn('test</code> <strong><span class="red">error</span></strong>', report.render(result))

    def test_serialized_json_size_bound(self):
        payload = osc(b"state=working:id=x") + b'# Program status: state=working id=x msg="' + b"\xc3\xa9" * 900 + b'"\n'
        result = report.extract(payload * 1000, True)
        with tempfile.TemporaryDirectory() as directory:
            report.write_report(result, directory)
            for path in Path(directory).iterdir():
                self.assertLessEqual(path.stat().st_size, report.MAX_ARTIFACT)
            saved = json.loads((Path(directory) / "events.v1.json").read_text())
        self.assertIn("artifact size limit", saved["source"]["limited"])
        self.assertGreater(len(saved["events"]), 0)
        self.assertEqual([e["sequence"] for e in saved["events"]], list(range(1, len(saved["events"]) + 1)))

    def test_annotation_display_limits_leave_json_history_intact(self):
        data = b"".join(osc(b"state=blocked:id=build/test" + str(i).encode() + b":progress=37:kind=permission")
                        + b'# Program status: state=blocked id=build/test' + str(i).encode()
                        + b' kind=permission progress=37 msg="' + b"'" * 600 + b'"\n' for i in range(300))
        result = report.extract(data, True)
        with tempfile.TemporaryDirectory() as directory:
            report.write_report(result, directory)
            saved = json.loads((Path(directory) / "events.v1.json").read_text())
        page = report.render(result, "osc7501/synthetic-job/events.v1.json")
        self.assertLessEqual(len(page.encode()), report.MAX_ANNOTATION)
        self.assertIn('kind=permission · progress=37', page)
        self.assertIn('… (shortened)', page)
        self.assertIn('Other programs are omitted', page)
        self.assertEqual(page.count('<li><details open>'), 100)
        rows = HistoryRows(page).rows
        self.assertGreater(len(rows), 0)
        self.assertLess(len(rows), 300)
        self.assertEqual([int(row[0]) for row in rows], list(range(1, len(rows) + 1)))
        self.assertEqual(rows[-1][1], 'build/test' + str(len(rows) - 1))
        self.assertIn('History limited to the first ' + str(len(rows)) + ' of 300 reports', page)
        self.assertEqual(len(saved["events"]), 300)
        self.assertEqual(saved["source"]["limited"], [])
        self.assertEqual(len(saved["events"][-1]["details"]), 606)
        self.assertIn('artifact://osc7501/synthetic-job/events.v1.json', page)
        self.assertNotIn('artifact://', report.render(result))

    def test_local_cli_writes_annotation_preview_and_json(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(["python3", "-I", str(ROOT / "lib/report.py"), "local",
                            str(ROOT / "tests/fixtures/failed.raw"), directory, "--include-details"], check=True)
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ["annotation.html", "events.v1.json"])
            self.assertEqual(json.loads((Path(directory) / "events.v1.json").read_text())["schema_version"], 1)
            page = (Path(directory) / "annotation.html").read_text()
            self.assertIn("OSC-7501 Events", page)
            self.assertIn("JSON artifact not uploaded", page)
            self.assertNotIn("<script", page)
            self.assertNotIn("<style", page)
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
    def test_hook_preserves_outcomes_when_log_upload_or_annotation_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            agent = Path(directory) / "buildkite-agent"
            agent.write_text(AGENT_STAND_IN)
            agent.chmod(0o755)
            env = {"PATH": directory + os.pathsep + os.defpath + ":/usr/local/bin", "CAPTURE": directory,
                   "BUILDKITE_JOB_ID": "synthetic-job"}
            for status in ("0", "7"):
                for upload_exit, annotate_exit in (("0", "0"), ("0", "9"), ("9", "0"), ("9", "9")):
                    env.update(UPLOAD_EXIT=upload_exit, ANNOTATE_EXIT=annotate_exit)
                    result = subprocess.run(["bash", "-c", 'bash -c "exit $1"; export BUILDKITE_COMMAND_EXIT_STATUS=$?; "$2"; hook_status=$?; test "$hook_status" = 0 || exit 99; exit "$BUILDKITE_COMMAND_EXIT_STATUS"',
                                             "test", status, str(ROOT / "hooks/post-command")], env=env, capture_output=True)
                    self.assertEqual(result.returncode, int(status))
                    self.assertIn(b"log snapshot unavailable", result.stdout)
                    self.assertNotIn(b"DO_NOT_LOG_AGENT_PAYLOAD", result.stdout + result.stderr)
                    self.assertEqual((Path(directory) / "upload-args").read_text().strip(),
                                     "artifact upload osc7501/synthetic-job/events.v1.json")
                    saved = json.loads((Path(directory) / "events.v1.json").read_text())
                    self.assertEqual(saved["source"]["availability"], "unavailable")
                    page = (Path(directory) / "annotation.html").read_text()
                    self.assertIn("Log snapshot unavailable", page)
                    self.assertIn('href="?jid=synthetic-job&amp;tab=output#synthetic-job">Open job log</a>', page)
                    self.assertEqual("artifact://" in page, upload_exit == "0")
                    self.assertEqual(b"job annotation unavailable" in result.stdout, annotate_exit != "0")
                    if upload_exit != "0":
                        self.assertIn(b"artifact upload unavailable", result.stdout)

    def test_local_file_to_artifact_upload_with_default_options(self):
        with tempfile.TemporaryDirectory() as directory:
            agent = Path(directory) / "buildkite-agent"
            agent.write_text(AGENT_STAND_IN)
            agent.chmod(0o755)
            env = {"PATH": directory + os.pathsep + os.defpath + ":/usr/local/bin", "CAPTURE": directory,
                   "BUILDKITE_JOB_ID": "synthetic-job"}
            for scenario, count, status in (("failed", 13, 7), ("successful", 13, 0),
                                            ("blocked", 15, 0), ("experiment-off", 0, 0)):
                with self.subTest(scenario=scenario):
                    env["BUILDKITE_JOB_ID"] = "synthetic-" + scenario
                    artifact_path = "osc7501/synthetic-" + scenario + "/events.v1.json"
                    env["BUILDKITE_JOB_LOG_TMPFILE"] = str(ROOT / "tests/fixtures" / (scenario + ".raw"))
                    # Run an actual command, then the optional hook, preserving its result.
                    result = subprocess.run(["bash", "-c", 'bash -c "exit $1"; export BUILDKITE_COMMAND_EXIT_STATUS=$?; "$2"; exit "$BUILDKITE_COMMAND_EXIT_STATUS"',
                                             "test", str(status), str(ROOT / "hooks/post-command")], env=env, capture_output=True)
                    self.assertEqual(result.returncode, status)
                    self.assertEqual(result.stdout + result.stderr, b"")
                    saved = json.loads((Path(directory) / "events.v1.json").read_text())
                    self.assertEqual(saved["source"]["availability"], "available")
                    self.assertEqual(len(saved["events"]), count)
                    self.assertEqual((Path(directory) / "uploaded-files").read_text().splitlines(),
                                     [artifact_path])
                    self.assertEqual((Path(directory) / "annotation-args").read_text().strip(),
                                     "annotate --scope job --job synthetic-" + scenario
                                     + " --context osc7501-synthetic-" + scenario + " --style info --append=false")
                    page = (Path(directory) / "annotation.html").read_text()
                    self.assertIn("artifact://" + artifact_path, page)
                    self.assertIn('href="?jid=synthetic-' + scenario + '&amp;tab=output#synthetic-'
                                  + scenario + '">Open job log</a>', page)
                    self.assertNotIn('/L', page)
                    self.assertTrue(all("details" not in e for e in saved["events"]))
                    if count:
                        self.assertEqual([e["state"] for e in saved["events"]][-2:], ["clear", "clear"])
                        self.assertEqual([row[2] for row in HistoryRows(page).rows],
                                         [e["state"] for e in saved["events"]])
                    else:
                        self.assertEqual(saved["source"]["event_support"], "unknown")
            env[report.PREFIX + "INCLUDE_DETAILS"] = "true"
            env["BUILDKITE_JOB_LOG_TMPFILE"] = str(ROOT / "tests/fixtures/failed.raw")
            subprocess.run([str(ROOT / "hooks/post-command")], env=env, check=True)
            saved = json.loads((Path(directory) / "events.v1.json").read_text())
            self.assertEqual(len(saved["events"]), 13)
            self.assertIn("Compiling", next(e["details"] for e in saved["events"] if "details" in e))

    def test_parse_failure_and_delivery_timeouts_are_fail_open(self):
        with tempfile.TemporaryDirectory() as directory:
            agent = Path(directory) / "buildkite-agent"
            agent.write_text(AGENT_STAND_IN)
            agent.chmod(0o755)
            env = {"PATH": directory + os.pathsep + os.defpath, "CAPTURE": directory,
                   "BUILDKITE_JOB_ID": "synthetic-job",
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
                        self.assertIn("job annotation unavailable", output.getvalue())
                    self.assertEqual(os.environ["BUILDKITE_COMMAND_EXIT_STATUS"], status)
            # Never fall back to a build-scoped annotation without a job context.
            (Path(directory) / "annotation-args").unlink()
            for invalid_job in ("", "../outside", "a" * 65):
                env["BUILDKITE_JOB_ID"] = invalid_job
                with patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(io.StringIO()) as output:
                    report.hook()
                self.assertIn("job annotation unavailable", output.getvalue())
                self.assertFalse((Path(directory) / "annotation-args").exists())
                self.assertEqual((Path(directory) / "uploaded-files").read_text().strip(), "osc7501/events.v1.json")


if __name__ == "__main__":
    unittest.main()
