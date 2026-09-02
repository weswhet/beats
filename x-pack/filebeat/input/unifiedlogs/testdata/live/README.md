# Unified logs live test harness

This directory contains a local end-to-end harness for the native macOS
Unified Logs input. Filebeat sends events over the Beats protocol to Logstash
OSS, and Logstash writes one JSON object per line for inspection. Run these
commands from the repository root on macOS.

## Start Logstash OSS

The arm64 macOS distribution below is the server used to verify this harness.
Use the corresponding x86_64 artifact on an Intel Mac.

```sh
logstash_version=9.5.2
work_dir="$(mktemp -d)"
artifact="logstash-oss-${logstash_version}-darwin-aarch64.tar.gz"

curl -fL "https://artifacts.elastic.co/downloads/logstash/${artifact}" \
  -o "${work_dir}/${artifact}"
curl -fL "https://artifacts.elastic.co/downloads/logstash/${artifact}.sha512" \
  -o "${work_dir}/${artifact}.sha512"
(cd "${work_dir}" && shasum -a 512 -c "${artifact}.sha512")
tar -xzf "${work_dir}/${artifact}" -C "${work_dir}"

event_file="${work_dir}/received.jsonl"
FILEBEAT_UNIFIEDLOGS_E2E_OUTPUT="${event_file}" \
  "${work_dir}/logstash-${logstash_version}/bin/logstash" \
  --pipeline.ecs_compatibility disabled \
  --path.data "${work_dir}/logstash-data" \
  -f x-pack/filebeat/input/unifiedlogs/testdata/live/logstash.conf
```

Logstash listens for Beats traffic on port 5044. Its API is available on port
9600; `curl -s http://127.0.0.1:9600/_node/pipelines?pretty` should report a
green `main` pipeline before Filebeat is started. The equivalent container
image is `docker.elastic.co/logstash/logstash-oss:9.5.2`.

## Build and run Filebeat

Build the current source tree and always give live runs an isolated home and
registry:

```sh
(cd x-pack/filebeat && DEV=true mage build)
filebeat_home="$(mktemp -d)"

x-pack/filebeat/filebeat -e --strict.perms=false \
  -c "$PWD/x-pack/filebeat/input/unifiedlogs/testdata/live/filebeat-live.yml" \
  --path.home="${filebeat_home}" \
  --path.data="${filebeat_home}/data" \
  --path.logs="${filebeat_home}/logs"
```

`filebeat-live.yml` deliberately starts only these subscriptions:

- both test-emitter subsystems with Info, Debug, and signposts requested;
- those same subsystems with only Default, Error, and Fault retained; and
- the `trustd`, `runningboardd`, or `logd` processes, combined with OR.

The selected system processes can be noisy. Keep that run brief. The missing
module-directory warning is expected when `path.home` is an empty temporary
directory.

## Emit controlled OSLog records

While Filebeat is running, use the companion Swift package to write modern
`Logger`, legacy `os_log`, signpost, activity, structured, multiline, private,
and all-level records:

```sh
xcodebuildmcp swift-package run --json \
  '{"packagePath":"x-pack/filebeat/input/unifiedlogs/testdata/oslog-emitter","executableName":"unifiedlogs-emitter","arguments":["--run-id","live-001"],"configuration":"debug","timeout":30}'
```

Use a new run ID for each emission. macOS can discard Debug records before any
reader sees them; `debug: true` requests them but cannot recover discarded
records.

## Focused configurations

The other configurations exercise one behavior at a time:

| Configuration | Behavior |
| --- | --- |
| `filebeat-stream.yml` | One emitter subscription for stream/fallback and restart-cursor tests |
| `filebeat-backfill.yml` | Concurrent historic Store backfill plus live collection |
| `filebeat-bounded.yml` | Inclusive `start`/`end` Store one-shot; set `UNIFIEDLOGS_E2E_START` and `UNIFIEDLOGS_E2E_END` |
| `filebeat-archive.yml` | `.logarchive` Store one-shot; set `UNIFIEDLOGS_E2E_ARCHIVE` |
| `filebeat-rejected.yml` | Expected startup failure listing every unsupported legacy option |

For example, run a one-second inclusive time window with:

```sh
UNIFIEDLOGS_E2E_START='2026-09-01 22:16:09-0700' \
UNIFIEDLOGS_E2E_END='2026-09-01 22:16:10-0700' \
  x-pack/filebeat/filebeat -e --strict.perms=false \
  -c "$PWD/x-pack/filebeat/input/unifiedlogs/testdata/live/filebeat-bounded.yml" \
  --path.home="${filebeat_home}" \
  --path.data="${filebeat_home}/data" \
  --path.logs="${filebeat_home}/logs"
```

To exercise the checked-in archive:

```sh
archive_dir="$(mktemp -d)"
tar -xzf x-pack/filebeat/input/unifiedlogs/testdata/test.logarchive.tar.gz \
  -C "${archive_dir}"
UNIFIEDLOGS_E2E_ARCHIVE="${archive_dir}/test.logarchive" \
  x-pack/filebeat/filebeat -e --strict.perms=false \
  -c "$PWD/x-pack/filebeat/input/unifiedlogs/testdata/live/filebeat-archive.yml" \
  --path.home="${filebeat_home}" \
  --path.data="${filebeat_home}/data" \
  --path.logs="${filebeat_home}/logs"
```

An `end` or `archive_file` input completes after its fixed Store snapshot.
Filebeat itself remains available for other inputs, so stop the process after
the output ACK is logged.

## Inspect results

The outer `message` is compact JSON. These commands summarize the test source
and inspect the native payload:

```sh
jq -s 'group_by(.e2e_source) | map({source: .[0].e2e_source, count: length})' \
  "${event_file}"

jq -r 'select(.e2e_source == "emitter_all") | .message | fromjson |
  [.timestamp, .eventType, .messageType, .process, .subsystem, .eventMessage] |
  @tsv' "${event_file}"
```

During continuous runs, `http://127.0.0.1:5066/inputs/` exposes
`stream_fallbacks_total`, `duplicates_dropped_total`, `errors_total`, and
published-event counters. Restart `filebeat-stream.yml` with the same
`path.data` to verify that the five-second overlap increases only the duplicate
counter and does not append already acknowledged events to `received.jsonl`.
