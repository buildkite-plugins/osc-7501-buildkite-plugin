# OSC-7501 Buildkite plugin

Turn a step's OSC 7501 program reports into two artifacts:

- `osc7501/report.html`: a self-contained event tree and chronological history.
- `osc7501/events.v1.json`: chronological reports with schema version 1.

The plugin reads the agent's local log file in `post-command`, without wrapping your command or requiring a REST API token.

## Usage

Requires a POSIX agent with Bash, Python 3.9+, `buildkite-agent`, and OSC 7501 output.

Enable the local log file in your [agent configuration](https://buildkite.com/docs/agent/v3/configuration), then restart the agent:

```ini
enable-job-log-tmpfile=true
# Optional: agent lifecycle events and readable descriptions
experiment="program-status"
```

The hook must be able to read `BUILDKITE_JOB_LOG_TMPFILE`, including across container mounts. Isolate the log directory: files have mode `0644` and are deleted after the job.

The plugin does not enable experiments or instrument commands.

Add the plugin to your step. No release is published yet; replace `COMMIT_SHA` with a reviewed commit before use:

```yaml
steps:
  - command: ./run-tests
    plugins:
      - mcncl/osc-7501#COMMIT_SHA: {}
```

Adding the plugin enables reporting. Remove it from the step to stop generating reports.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `include-details` | `false` | Include adjacent, matching, already-redacted readable descriptions. |

## Reading the report

Download `report.html` from the step's artifacts and open it locally. No external assets or scripts are needed; inline viewing in Buildkite is not guaranteed.

The tree groups by `/` in program IDs. Tools are not implicitly children of the command. History retains successful hooks, repeats, progress, and clear reports; clear removes live records and descendants, not history.

Reports are **partial**, not job status: buffered output and later hooks may be missing. Setup failures, hard cancellation, or agent loss can prevent reporting. Line numbers are snapshot-local; no timestamps, durations, or native log links are inferred.

- **Unavailable:** the log could not be read.
- **Unknown:** no supported events observed, not evidence of success.
- **Limited:** malformed reports or resource limits shortened extraction.

## Data and limits

**Artifacts have separate access and retention from logs and are not automatically redacted.** Review before adding the plugin; removing it does not delete existing artifacts.

Reads happen after normal agent redaction. Ordinary output and encoded title/message fields are excluded; raw logs are never uploaded. Optional readable details are position-matched, not authenticated. Unregistered secrets can remain in metadata or details.

## Development

```sh
python3 -m unittest discover -s tests -v
bash -n hooks/post-command
python3 -I lib/report.py local tests/fixtures/failed.raw /tmp/osc7501-demo --include-details
```
