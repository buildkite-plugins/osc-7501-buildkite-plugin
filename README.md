# OSC-7501 Buildkite plugin

Show a step's OSC 7501 program reports in a job-level **OSC-7501 Events** annotation and upload chronological JSON to `osc7501/<job-id>/events.v1.json` (schema version 1).

Reads the agent's local log in `post-command`. No command wrapping or REST API token required.

## Usage

Requires a POSIX agent with Bash, Python 3.9+, OSC 7501 output, and a `buildkite-agent` version supporting `annotate --scope job` (verified in v4.8.1).

Enable the local log file in your [agent configuration](https://buildkite.com/docs/agent/v3/configuration), then restart the agent:

```ini
enable-job-log-tmpfile=true
# Optional: agent lifecycle events and readable descriptions
experiment="program-status"
```

The hook needs access to `BUILDKITE_JOB_LOG_TMPFILE`, including across container mounts. Isolate its directory: log files have mode `0644`. The plugin does not enable experiments or instrument commands.

```yaml
steps:
  - command: ./run-tests
    plugins:
      - mcncl/osc-7501#v1.2.0: ~
```

`include-details` defaults to `false`. Enable it to copy adjacent, matching, already-redacted readable descriptions.

Reports are partial, not job status; reporting failures leave the command's exit status unchanged. Adding the plugin copies log-derived data into annotations and artifacts with separate access and retention. Removing it does not delete existing copies. Artifact contents are not automatically redacted; unregistered secrets can remain.

## Development

```sh
python3 -m unittest discover -s tests -v
bash -n hooks/post-command
python3 -I lib/report.py local tests/fixtures/failed.raw /tmp/osc7501-demo --include-details
```

Local mode writes `annotation.html` and `events.v1.json` without uploads or annotation writes. Use synthetic or already-redacted inputs. Local previews do not verify Buildkite sanitization or artifact links.
