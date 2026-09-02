# Unified logs emitter

`unifiedlogs-emitter` is a small macOS command-line fixture for exercising the
native Unified Logs reader. It writes one deterministic run of records using
both the modern `Logger` API (when available) and the legacy `os_log` API.

Every record contains the public `run=<run-id>` token, an emitter version, and
a stable `sequence=NN` marker. Pass a distinct `--run-id` for each test run so
that a Filebeat predicate can select exactly one run:

```text
subsystem == "co.elastic.filebeat.unifiedlogs.e2e.primary" && composedMessage CONTAINS "run=live-001"
```

The primary subsystem is `co.elastic.filebeat.unifiedlogs.e2e.primary`. The
secondary subsystem is `co.elastic.filebeat.unifiedlogs.e2e.secondary`.
The emitter uses these categories:

* `logger` and `payload` for `Logger` records;
* `os_log` and `legacy` for legacy records;
* `signpost` for signpost begin/event/end records; and
* `activity` for records scoped by `os_activity_initiate`.

## Build

Run on macOS with the Xcode command-line tools selected. The repository's
macOS development workflow uses XcodeBuildMCP:

```sh
xcodebuildmcp swift-package build \
  --package-path x-pack/filebeat/input/unifiedlogs/testdata/oslog-emitter \
  --target-name unifiedlogs-emitter \
  --configuration debug \
  --architectures arm64
```

Use `--architectures x86_64` for an Intel build. The package keeps the
deployment target at macOS 10.15: `Logger` records are guarded for macOS 11 and
newer, while `os_log`, signposts, and activity records remain usable on the
older target.

## Run

The default run ID is `run-default`; pass an explicit value for assertions.
Through XcodeBuildMCP:

```sh
xcodebuildmcp swift-package run --json \
  '{"packagePath":"x-pack/filebeat/input/unifiedlogs/testdata/oslog-emitter","executableName":"unifiedlogs-emitter","arguments":["--run-id","live-001"],"configuration":"debug","timeout":30}'
```

Or run the built product directly:

```sh
.build/debug/unifiedlogs-emitter --run-id live-001
```

The command prints `EMITTER_START` and `EMITTER_DONE` markers to stdout. To
leave the process alive while a live Filebeat input is started, use
`--hold-ms`, for example `--hold-ms 5000`. Use `--no-activity` when testing a
platform where activity APIs are unavailable.

For a quick diagnostic read with Apple's command-line viewer, include all
optional levels and signposts:

```sh
log show --last 1m --info --debug --signpost --style json \
  --predicate 'subsystem BEGINSWITH "co.elastic.filebeat.unifiedlogs.e2e" AND composedMessage CONTAINS "run=live-001"'
```

Debug records can be disabled by the host logging configuration; Filebeat's
`debug: true` option requests them from the native reader but cannot make the
operating system persist records that were discarded at emission time.

The event sequence is:

* `01`–`09`: `Logger` default/info/debug/error/fault, structured public
  values, public/private interpolation, multiline text, and the secondary
  subsystem/category;
* `10`–`18`: corresponding legacy `os_log` levels and payload records;
* `19`–`21`: signpost interval begin, event, and end; and
* `22`–`24`: activity-scoped default/info/default records.

Private values are intentionally redacted by Unified Logs unless the reader
has permission to resolve them. The run ID is always public so records remain
selectable.
