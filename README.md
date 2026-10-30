# OSC-7501 Buildkite plugin

Turn a step's OSC 7501 program reports into:

- A job-level **OSC-7501 Events** annotation with a program-ID tree and latest observed states.
- `osc7501/<job-id>/events.v1.json`: chronological reports with schema version 1. Job-specific paths keep parallel jobs' artifact links distinct.

The plugin reads the agent's local log file in `post-command`, without wrapping your command or requiring a REST API token.

## Usage

Requires a POSIX agent with Bash, Python 3.9+, OSC 7501 output, and a `buildkite-agent` version supporting `annotate --scope job` (verified in v4.8.1).

Enable the local log file in your [agent configuration](https://buildkite.com/docs/agent/v3/configuration), then restart the agent:

```ini
enable-job-log-tmpfile=true
# Optional: agent lifecycle events and readable descriptions
experiment="program-status"
```

The hook must be able to read `BUILDKITE_JOB_LOG_TMPFILE`, including across container mounts. Isolate the log directory: files have mode `0644` and are deleted after the job.

The plugin does not enable experiments or instrument commands.

Add the plugin to your step:

```yaml
steps:
  - command: ./run-tests
    plugins:
      - mcncl/osc-7501#v1.0.0: ~
```

Adding the plugin enables reporting on that step. Remove it from the step to stop generating reports.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `include-details` | `false` | Include adjacent, matching, already-redacted readable descriptions. |

## Reading the report

Read **OSC-7501 Events** on the job. **Open job log** switches to that job's output tab, without targeting a specific line. The annotation also links to chronological JSON when its artifact upload succeeds. No HTML artifact is uploaded.

The tree groups by `/` in program IDs. Each group can be collapsed and starts expanded. Tools are not implicitly children of the command. The annotation shows latest observed states and report counts, including cleared records and their last state before clear.

Open the separate **Chronological history** section to see reports in snapshot order, including successful hooks, repeats, progress, and clear reports. Clear removes live records and descendants, not history. This section starts collapsed.

Annotations show at most 100 tree nodes and 200 characters of each readable description. History shows the first reports that fit within the 256 KiB annotation limit, with a notice when reports are omitted. Display limits do not shorten JSON history. Extraction is bounded to the first 2 MiB of logs and 1000 events; the JSON artifact is limited to 2 MiB.

Reports are **partial**, not job status: buffered output and later hooks may be missing. Setup failures, hard cancellation, or agent loss can prevent reporting. Line numbers are snapshot-local; no timestamps, durations, or exact native log-line links are inferred.

- **Unavailable:** the log could not be read.
- **Unknown:** no supported events observed, not evidence of success.
- **Limited:** malformed reports or resource limits shortened extraction.

## Data and limits

**Annotations and artifacts copy log-derived data outside the log.** Review their access and retention before adding the plugin. Removing the plugin does not delete existing annotations or artifacts, and artifact contents are not automatically redacted.

Reads happen after normal agent redaction. Ordinary output and encoded title/message fields are excluded; raw logs are never uploaded. Optional readable details are position-matched, not authenticated. Unregistered secrets can remain in metadata or details.

Reporting failures warn without changing the command's exit status. JSON upload and annotation delivery are attempted independently, with a 15-second timeout each. If job-scoped annotations are unsupported or job context is missing, the plugin does not fall back to build-scoped annotations.

## Development

```sh
python3 -m unittest discover -s tests -v
bash -n hooks/post-command
python3 -I lib/report.py local tests/fixtures/failed.raw /tmp/osc7501-demo --include-details
```

Local mode writes `annotation.html` (an HTML fragment for inspection) and `events.v1.json`, without uploads or annotation writes. Use synthetic or already-redacted inputs. Local rendering does not verify Buildkite's server-side sanitization or artifact-link resolution.
