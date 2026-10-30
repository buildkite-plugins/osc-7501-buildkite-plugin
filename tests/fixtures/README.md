# Synthetic capture provenance

These four captures came from local Buildkite agent bootstrap runs at public
agent revision `075fef3b78de0e5b6d7c356863dfbb7ea1aa13eb` using synthetic
build, test, and hook output. They contain no real job credentials or customer
logs. They are test inputs, not artifacts produced by this plugin.

- `failed.raw`: 13 OSC reports, test and command errors, two successful hooks,
  two clear reports, and a progress-only update without a readable description.
- `successful.raw`: 13 reports, successful test and command, successful hooks
  retained before clear.
- `blocked.raw`: 15 reports, permission-blocked build followed by resumed work
  and success. This does not represent an authoritative blocked job state.
- `experiment-off.raw`: ordinary synthetic output, no OSC reports. A consumer
  can infer only that no reports were observed, not that the experiment was off.

Only the adjacent readable descriptions may supply optional detail text.
Encoded title/message fields in these inputs must not be decoded into reports.
