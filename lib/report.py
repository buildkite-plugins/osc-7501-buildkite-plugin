"""Bounded OSC 7501 snapshot reporting, using only the standard library."""

import argparse
import html
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile


MAX_LOG = 2 * 1024 * 1024
MAX_SEQUENCE = 4096
MAX_FIELDS = 24
MAX_EVENTS = 1000
MAX_ARTIFACT = 2 * 1024 * 1024
MAX_TREE_NODES = 100
MAX_NODE_REPORTS = 5
MAX_ANNOTATION = 256 * 1024
STATES = {"idle", "working", "blocked", "done", "error", "clear"}
SEGMENT = re.compile(r"[A-Za-z0-9_.+-]{1,32}\Z")
SGR = re.compile(rb"\x1b\[[0-9;]*m")
TERMINATOR = re.compile(rb"\x07|\x1b\\")
PREFIX = "BUILDKITE_PLUGIN_OSC_7501_"


def metadata(body):
    # Deliberately a conservative subset of rev 0.4, not a base64 decoder.
    if len(body) > 4088 or len(body.split(b":")) > MAX_FIELDS:
        return None
    fields = {}
    for pair in body.split(b":"):
        if b"=" not in pair:
            continue
        key, value = pair.split(b"=", 1)
        if not re.fullmatch(rb"[a-z]{1,16}", key):
            return None
        if key in (b"title", b"msg"):
            limit = 256 if key == b"title" else 2732
            if len(value) > limit or not re.fullmatch(rb"[A-Za-z0-9+/]*={0,2}", value):
                return None
            continue
        if key in (b"state", b"id", b"app", b"kind", b"progress"):
            text = value.decode("ascii", errors="replace")
            # An invalid occurrence rejects the whole report, even before a valid duplicate.
            if key == b"id" and (not text or len(text) > 128 or len(text.split("/")) > 8
                                 or not all(SEGMENT.fullmatch(s) for s in text.split("/"))):
                return None
            if key == b"app" and not SEGMENT.fullmatch(text):
                return None
            fields[key.decode()] = text
    if fields.get("state") not in STATES:
        return None
    identifier = fields.get("id", "")
    result = {"state": fields["state"], "id": identifier}
    if "app" in fields:
        result["app"] = fields["app"]
    if fields["state"] == "blocked" and fields.get("kind") in {"permission", "question", "auth"}:
        result["kind"] = fields["kind"]
    progress = fields.get("progress", "")
    if fields["state"] in {"working", "blocked"} and re.fullmatch(r"[0-9]{1,3}", progress):
        result["progress"] = min(int(progress), 100)
    return result


def readable_details(tail, event):
    # Only the immediately adjacent description can belong to this report.
    # Never strip OSC per line: a malicious payload can contain newlines.
    line = re.sub(rb"^(?:\r\n|\n)", b"", tail[:8192], count=1)
    # The agent prefixes new lines in its local file with this timestamp code.
    line = re.sub(rb"^\x1b_bk;t=[0-9]{1,20}\x07", b"", line, count=1)
    line = SGR.sub(b"", line).split(b"\n", 1)[0].removesuffix(b"\r")
    if b"\x1b" in line or len(line) > 4096:
        return None
    prefix = "# Program status: state=" + event["state"]
    for key in ("id", "kind", "progress", "app"):
        if key in event and event[key] != "":
            prefix += " " + key + "=" + str(event[key])
    text = line.decode("utf-8", errors="replace")
    if not text.startswith(prefix):
        return None
    rest = text[len(prefix):]
    # Preserve the quoted, redacted text verbatim. Do not unescape it.
    if rest and re.fullmatch(r'(?: (?:title|msg)="(?:[^"\\\x00-\x1f]|\\[^\x00-\x1f])*"){1,2}', rest):
        return rest.strip()
    return None


def empty_report(availability="available"):
    return {"schema_version": 1, "source": {"availability": availability,
            "coverage": "partial", "event_support": "unknown", "limited": []}, "events": []}


def extract(data, include_details=False, limited=False):
    report = empty_report()
    reasons = set()
    if limited or len(data) > MAX_LOG:
        reasons.add("log byte limit")
    data = data[:MAX_LOG]
    position = 0
    line = 1
    # Frame all OSC strings over the whole snapshot. Non-OSC text never enters artifacts.
    while position < len(data):
        start = data.find(b"\x1b]", position)
        if start < 0:
            break
        line += data[position:start].count(b"\n")
        terminator = TERMINATOR.search(data, start + 2)
        if not terminator:
            reasons.add("unterminated OSC string")
            break
        end, stop = terminator.span()
        if data[start + 2:start + 7] == b"7501;":
            if data[start + 7:start + 8] == b"?":
                event = None
            elif stop - start > MAX_SEQUENCE:
                reasons.add("oversized OSC report")
                event = None
            else:
                event = metadata(data[start + 7:end])
                if event is None:
                    reasons.add("unsupported or malformed OSC report")
            if event is not None:
                if len(report["events"]) == MAX_EVENTS:
                    reasons.add("event count limit")
                    break
                event.update(sequence=len(report["events"]) + 1, snapshot_line=line)
                if include_details:
                    details = readable_details(data[stop:stop + 8192], event)
                    if details:
                        event["details"] = details
                report["events"].append(event)
        line += data[start:stop].count(b"\n")
        position = stop
    report["source"]["event_support"] = "observed" if report["events"] else "unknown"
    report["source"]["limited"] = sorted(reasons)
    return report


def render(report, artifact_path=None, job=None):
    escape = lambda value: html.escape(str(value), quote=True)

    def state_label(state):
        color = {"error": "red", "done": "green", "blocked": "orange", "working": "blue",
                 "idle": "muted", "clear": "muted", "cleared": "muted"}.get(state)
        return '<span class="' + color + '">' + escape(state) + '</span>' if color else escape(state)

    events = report["events"]
    source = report["source"]
    status = source["availability"] + " · partial snapshot"
    if source["limited"]:
        status += " · limited: " + ", ".join(source["limited"])
    nodes = {}
    live = {}
    for event in events:
        identifier = event["id"]
        if event["state"] == "clear":
            live = {key: value for key, value in live.items()
                    if key != identifier and not (identifier == "" or key.startswith(identifier + "/"))}
        else:
            live[identifier] = event
        parts = identifier.split("/") if identifier else ["(root record)"]
        branch = nodes
        for part in parts:
            branch = branch.setdefault(part, {"children": {}, "events": []})
            node = branch
            branch = branch["children"]
        node["events"].append(event)

    shown = 0
    omitted = False

    def tree(branch, path=""):
        nonlocal shown, omitted
        result = ""
        for name, node in branch.items():
            if shown == MAX_TREE_NODES:
                omitted = True
                break
            shown += 1
            identifier = (path + "/" + name).lstrip("/")
            key = "" if identifier == "(root record)" else identifier
            current = live.get(key)
            own = node["events"]
            label = current["state"] if current else ("cleared" if own else "group")
            summary = '<code>' + escape(name) + '</code> <strong>' + state_label(label) + '</strong>'
            if own:
                summary += ' · ' + str(len(own)) + ' reports'
                if current is None:
                    previous = next((e for e in reversed(own) if e["state"] != "clear"), None)
                    if previous:
                        summary += ' · last before clear: ' + state_label(previous["state"])
            if current:
                for field in ("app", "kind", "progress"):
                    if field in current:
                        summary += ' · ' + field + '=' + escape(current[field])
            body = ''
            if current and current.get("details"):
                detail = current["details"]
                body += '<p>' + escape(detail[:200]) + ('… (shortened)' if len(detail) > 200 else '') + '</p>'
            elif current:
                body += '<p>Readable details unavailable for the latest report.</p>'
            if own:
                if len(own) > MAX_NODE_REPORTS:
                    body += '<p>Showing the last ' + str(MAX_NODE_REPORTS) + ' of ' + str(len(own)) + ' reports for this program. See chronological history or JSON for earlier reports.</p>'
                body += '<ol>'
                for event in own[-MAX_NODE_REPORTS:]:
                    body += '<li>Report #' + str(event["sequence"]) + ' · ' + state_label(event["state"])
                    if "progress" in event:
                        body += ' · progress=' + str(event["progress"])
                    body += ' · snapshot line ' + str(event["snapshot_line"]) + '</li>'
                body += '</ol>'
            if node["children"]:
                body += tree(node["children"], identifier)
            result += '<li>'
            if body:
                result += '<details open><summary>' + summary + '</summary>' + body + '</details>'
            else:
                result += summary
            result += '</li>'
        return '<ul>' + result + '</ul>' if result else ''

    if not events:
        message = "Log snapshot unavailable. No event history can be determined." if source["availability"] == "unavailable" else "No supported events observed. Experiment support is unknown; this is not evidence of success."
        content = '<p>' + message + '</p>'
    else:
        content = '<p>' + str(len(events)) + ' chronological reports · grouped by program ID</p>' + tree(nodes)
        if omitted:
            content += '<p>Tree limited to ' + str(MAX_TREE_NODES) + ' nodes. Other programs are omitted from this summary.</p>'
        rows = []
        # Reserve space for the fixed header, history wrapper, notices and links.
        remaining = MAX_ANNOTATION - len(content.encode()) - 4096
        for event in events:
            extra = ' · '.join(key + '=' + str(event[key]) for key in ("app", "kind", "progress") if key in event)
            detail = event.get("details", "Details unavailable")
            row = ('<tr><td>' + str(event["sequence"]) + '</td><td><code>' + escape(event["id"] or '(root record)')
                   + '</code></td><td>' + state_label(event["state"]) + '</td><td>' + escape(extra)
                   + '<p>' + escape(detail[:200]) + ('… (shortened)' if len(detail) > 200 else '')
                   + '</p></td><td>' + str(event["snapshot_line"]) + '</td></tr>')
            size = len(row.encode())
            if size > remaining:
                break
            remaining -= size
            rows.append(row)
        if len(rows) < len(events):
            content += '<p>History limited to the first ' + str(len(rows)) + ' of ' + str(len(events)) + ' reports. JSON retains the remaining extracted reports.</p>'
        content += ('<details><summary>Chronological history (' + str(len(rows)) + ' of ' + str(len(events))
                    + ' reports)</summary><div class="overflow-auto"><table><thead><tr><th>#</th><th>Program ID</th>'
                    '<th>State</th><th>Details</th><th>Snapshot line</th></tr></thead><tbody>'
                    + ''.join(rows) + '</tbody></table></div></details>')
    link = ('<a href="artifact://' + escape(artifact_path) + '">Download chronological JSON</a>'
            if artifact_path else 'JSON artifact not uploaded.')
    if job:
        link += ' · <a href="?jid=' + escape(job) + '&amp;tab=output#' + escape(job) + '">Open job log</a>'
    body = ('<h3>OSC-7501 Events</h3><p><strong>' + escape(status) + '</strong></p>'
            '<p>Buffered output and later lifecycle reports may be missing. Program states are not job status.</p>'
            + content + '<p>' + link + '</p>'
            '<p>Cleared records remain in JSON history. Line numbers are snapshot-local, not Buildkite log viewer IDs.</p>')
    if len(body.encode()) > MAX_ANNOTATION:
        raise ValueError("annotation exceeds limit")
    return body


def write_report(report, directory):
    # Annotation display limits must not discard chronological JSON events.
    while True:
        encoded = json.dumps(report, ensure_ascii=True, separators=(",", ":")).encode()
        if len(encoded) <= MAX_ARTIFACT:
            break
        report["source"]["limited"] = sorted(set(report["source"]["limited"] + ["artifact size limit"]))
        if not report["events"]:
            raise ValueError("artifact envelope exceeds limit")
        del report["events"][len(report["events"]) // 2:]
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "events.v1.json").write_bytes(encoded)


def read_snapshot(path):
    def deadline(signum, frame):
        raise TimeoutError("log read deadline")

    previous = signal.signal(signal.SIGALRM, deadline)
    signal.alarm(10)
    try:
        # Nonblocking open prevents a substituted FIFO from hanging the hook.
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as response:
            if not stat.S_ISREG(os.fstat(response.fileno()).st_mode):
                raise ValueError("not a regular log file")
            # Take one bounded prefix, even while the agent continues appending.
            data = response.read(MAX_LOG + 1)
        return data[:MAX_LOG], len(data) > MAX_LOG
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def warn(message):
    # The shell suppresses unexpected interpreter diagnostics, not these fixed warnings.
    print("OSC 7501 report warning: " + message + "; command outcome unchanged")


def hook():
    report = empty_report("unavailable")
    try:
        data, limited = read_snapshot(os.environ["BUILDKITE_JOB_LOG_TMPFILE"])
        report = extract(data, os.environ.get(PREFIX + "INCLUDE_DETAILS") == "true", limited)
    except Exception:
        warn("log snapshot unavailable")
    job = os.environ.get("BUILDKITE_JOB_ID", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", job):
        job = ""
    artifact_path = "osc7501/" + (job + "/" if job else "") + "events.v1.json"
    artifact_uploaded = False
    try:
        with tempfile.TemporaryDirectory(prefix="osc7501-") as directory:
            write_report(report, (Path(directory) / artifact_path).parent)
            if report["source"]["limited"]:
                warn("snapshot extraction limited")
            # Use this step's existing agent job context, never a reporting step's token.
            subprocess.run(["buildkite-agent", "artifact", "upload", artifact_path], cwd=directory,
                           check=True, timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            artifact_uploaded = True
    except Exception:
        warn("report generation or artifact upload unavailable")
    try:
        if not job:
            raise ValueError("job context unavailable")
        subprocess.run(["buildkite-agent", "annotate", "--scope", "job", "--job", job,
                        "--context", "osc7501-" + job, "--style", "info", "--append=false"],
                       input=render(report, artifact_path if artifact_uploaded else None, job).encode(), check=True, timeout=15,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        warn("job annotation unavailable")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("hook")
    local = sub.add_parser("local", help="Read only a synthetic or already-redacted local snapshot; no upload")
    local.add_argument("input", type=Path)
    local.add_argument("output", type=Path)
    local.add_argument("--include-details", action="store_true")
    args = parser.parse_args()
    if args.command == "hook":
        hook()
    else:
        data, limited = read_snapshot(args.input)
        report = extract(data, args.include_details, limited)
        write_report(report, args.output)
        (args.output / "annotation.html").write_text(render(report), encoding="utf-8")


if __name__ == "__main__":
    main()
