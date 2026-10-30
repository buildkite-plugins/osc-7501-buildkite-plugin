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


def render(report):
    escape = lambda value: html.escape(str(value), quote=True)
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

    def tree(branch, path=""):
        result = "<ul>"
        for name, node in branch.items():
            identifier = (path + "/" + name).lstrip("/")
            key = "" if identifier == "(root record)" else identifier
            current = live.get(key)
            own = node["events"]
            label = current["state"] if current else ("cleared" if own else "group")
            result += '<li><details open><summary><code>' + escape(name) + '</code> <span class="state ' + label + '">' + label + '</span>'
            if own:
                result += ' <a href="#event-' + str(own[-1]["sequence"]) + '">' + str(len(own)) + ' reports</a>'
            result += "</summary>"
            if own:
                result += '<p class="record">' + escape(identifier) + "</p>"
            if node["children"]:
                result += tree(node["children"], identifier)
            result += "</details></li>"
        return result + "</ul>"

    rows = []
    for event in events:
        extra = " · ".join(k + "=" + str(event[k]) for k in ("app", "kind", "progress") if k in event)
        rows.append('<tr id="event-' + str(event["sequence"]) + '"><td>' + str(event["sequence"]) + '</td><td><code>' + escape(event["id"] or "(root record)") + '</code></td><td><span class="state ' + event["state"] + '">' + event["state"] + '</span></td><td>' + escape(extra) + '<div class="detail">' + escape(event.get("details", "Details unavailable")) + '</div></td><td>' + str(event["snapshot_line"]) + '</td></tr>')
    if not events:
        message = "Log snapshot unavailable. No event history can be determined." if source["availability"] == "unavailable" else "No supported events observed. Experiment support is unknown; this is not evidence of success."
        content = '<p class="notice">' + message + '</p>'
    else:
        content = '<section><h2>Event tree <small>Grouped by program ID</small></h2>' + tree(nodes) + '</section><section><h2>Chronological reports <small>' + str(len(events)) + ' reports</small></h2><div class="scroll"><table><thead><tr><th>#</th><th>Program ID</th><th>State</th><th>Details</th><th>Snapshot line</th></tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div></section>'
    return '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>OSC 7501 event snapshot</title><style>
table{min-width:720px}
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#f5f7fa;color:#192635;font:15px/1.5 system-ui,sans-serif}main{max-width:1200px;margin:auto;padding:36px 24px}h1{margin:0;font-size:30px}h2{font-size:20px;margin:0 0 18px}small{font-size:13px;color:#536476;font-weight:400;margin-left:10px}header{margin-bottom:26px}.notice{background:#fff4d9;border-left:4px solid #aa7000;padding:14px 18px}.scope{color:#536476;max-width:1000px}section{background:white;border:1px solid #d8e0e8;border-radius:8px;padding:22px;margin:20px 0}ul{list-style:none;margin:4px 0;padding-left:24px}section>ul{padding-left:0}li{border-left:1px solid #d8e0e8;padding-left:14px}summary{cursor:pointer;padding:7px;border-radius:4px;overflow-wrap:anywhere}summary:hover,summary:focus-visible{background:#edf3fc}.record{color:#536476;font-size:12px;margin:0 0 8px 24px}a{color:#265bae;font-size:12px}a:hover{text-decoration-thickness:2px}.state{display:inline-block;font-size:12px;border-radius:4px;padding:2px 7px;background:#e9eef4;color:#3e5065;margin-left:5px}.working{background:#e5edff;color:#204ea0}.done{background:#def4e8;color:#14633c}.error{background:#ffe3e1;color:#962d28}.blocked{background:#fff0c7;color:#795500}table{width:100%;border-collapse:collapse;text-align:left;font-size:13px}th{font-weight:600;color:#536476;background:#f5f7fa}td,th{padding:12px 10px;border-bottom:1px solid #e3e8ef;vertical-align:top}td{overflow-wrap:anywhere}tr:target{background:#fff4d9}.detail{white-space:pre-wrap;color:#536476;margin-top:5px;max-width:480px}.scroll{overflow:auto}code{font-size:13px}footer{color:#536476;font-size:12px}@media(max-width:600px){main{padding:20px 12px}section{padding:14px}h1{font-size:25px}small{display:block;margin:4px 0}ul{padding-left:12px}}
</style></head><body><main><header><h1>OSC-7501 Events</h1><p class="notice">''' + escape(status) + '''</p><p class="scope">Buffered output and later lifecycle reports may be missing. Program states are not job status.</p></header>''' + content + '''<footer>Cleared records remain in history. Line numbers refer to this snapshot, not the Buildkite log viewer.</footer></main></body></html>'''


def write_report(report, directory):
    # Both serialized artifacts are independently bounded, including HTML expansion.
    while True:
        encoded = json.dumps(report, ensure_ascii=True, separators=(",", ":")).encode()
        page = render(report).encode()
        if max(len(encoded), len(page)) <= MAX_ARTIFACT:
            break
        report["source"]["limited"] = sorted(set(report["source"]["limited"] + ["artifact size limit"]))
        if not report["events"]:
            raise ValueError("artifact envelope exceeds limit")
        del report["events"][len(report["events"]) // 2:]
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "events.v1.json").write_bytes(encoded)
    (directory / "report.html").write_bytes(page)


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
    try:
        with tempfile.TemporaryDirectory(prefix="osc7501-") as directory:
            write_report(report, Path(directory) / "osc7501")
            if report["source"]["limited"]:
                warn("snapshot extraction limited")
            # Use this step's existing agent job context, never a reporting step's token.
            subprocess.run(["buildkite-agent", "artifact", "upload", "osc7501/*"], cwd=directory,
                           check=True, timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        warn("report generation or artifact upload unavailable")


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
        write_report(extract(data, args.include_details, limited), args.output)


if __name__ == "__main__":
    main()
