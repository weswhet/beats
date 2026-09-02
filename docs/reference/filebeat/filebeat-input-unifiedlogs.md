---
navigation_title: "Unified Logs"
mapped_pages:
  - https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-unifiedlogs.html
applies_to:
  stack: ga
  serverless: ga
---

# Unified Logs input [filebeat-input-unifiedlogs]


::::{note}
Only available for macOS.
::::


The unified logging system provides a comprehensive and performant API to capture telemetry across all levels of macOS. It centralizes log data in memory and on disk instead of writing it to a text-based log file.

The input uses native macOS unified logging APIs. `OSLogStore` reads historical events, resumes a source, applies time bounds, and reads `.logarchive` bundles. Live collection uses the private `OSLogEventLiveStore` and `OSLogEventLiveStream` APIs when they are available. If that stream cannot be activated or becomes invalid, the input permanently switches to native `OSLogStore` snapshots until Filebeat is restarted. Snapshots are taken every second after a two-second settling delay and use a five-second overlap to avoid losing events. The input never invokes or falls back to the `log` command-line tool.

The input starts collecting from the current point in time unless a start date or the `backfill` option is set. On restart, a native cursor resumes from the previous high-water mark and removes events already acknowledged. A legacy timestamp-only cursor is accepted and may replay events from the first five-second overlap while event IDs are learned.

An `archive_file` or an `end` date makes the operation one-shot. After the bounded history or archive has been read, the input stops. `backfill` can be combined with live collection to read historical events and then continue streaming.

Reading the system store generally requires administrator privileges and an unsandboxed process. Run Filebeat with the permissions needed to access the system log store and any archive path; the input cannot elevate its own privileges. Native APIs require macOS 10.15 or newer.

Other configuration options can be specified to filter what events to process.

Example configuration:

Process all old and new logs:

```yaml
filebeat.inputs:
- type: unifiedlogs
  id: unifiedlogs-id
  enabled: true
  backfill: true
```

Process logs with predicate filters:

```yaml
filebeat.inputs:
- type: unifiedlogs
  id: unifiedlogs-id
  enabled: true
  predicate:
    # Captures keychain.db unlock events
    - 'process == "loginwindow" && sender == "Security"'
    # Captures user login events
    - 'process == "logind"'
    # Captures command line activity run with elevated privileges
    - 'process == "sudo"'
```

## Configuration options [_configuration_options_21]

The `unifiedlogs` input supports the following configuration options plus the [Common options](filebeat-input-unifiedlogs.md#filebeat-input-unifiedlogs-common-options) described later.


### `archive_file` [_archive_file]

Display events stored in the given archive. The archive must be a valid log archive bundle with the suffix `.logarchive`. Archive reads use `OSLogStore` and stop when the archive has been read.


### `start` [_start]

Shows content starting from the provided date. The start bound is inclusive. The following date/time formats are accepted: `YYYY-MM-DD`, `YYYY-MM-DD HH:MM:SS`, `YYYY-MM-DD HH:MM:SSZZZZZ`.


### `end` [_end]

Shows content up to the provided date. The end bound is inclusive. The following date/time formats are accepted: `YYYY-MM-DD`, `YYYY-MM-DD HH:MM:SS`, `YYYY-MM-DD HH:MM:SSZZZZZ`.


### `predicate` [_predicate]

Filters messages using the provided predicate based on NSPredicate. Multiple predicate entries are combined with OR. A compound predicate or multiple predicates can be provided as a list.

For detailed information on the use of predicate based filtering, please refer to the [Predicate Programming Guide](https://developer.apple.com/library/mac/documentation/Cocoa/Conceptual/Predicates/Articles/pSyntax.html).


### `process` [_process]

A list of processes on which to operate. It accepts a PID or process name. Multiple process selectors are combined with OR.


### `info` [_info]

Enable info level messages. Default: `false`.


### `debug` [_debug]

Enable debug level messages. Default: `false`.


### `signpost` [_signpost]

Enable signpost events. Default: `false`.


### `backfill` [_backfill]

If set to true the input will process all available logs since the beginning of time the first time it starts. Default: `false`.


## Rejected options [_rejected_options]

The following options belonged to the former `log` command-line implementation and are not available with the native APIs. Configuring any of them is an explicit configuration error; they are never silently ignored:

* `trace_file` — native readers accept a `.logarchive` bundle through `archive_file`, not an individual `.tracev3` file.
* `source` — native events do not expose the command-line source annotation.
* `backtrace` — native events do not expose command-line backtrace output.
* `unreliable` — native events do not expose the command-line reliability annotation.
* `mach_continuous_time` — native events use their wall-clock event date.


## Event fields [_event_fields]

The outer Filebeat event shape is unchanged. The outer event timestamp is the native event date and `message` contains compact JSON. The JSON contains these best-effort CLI-compatible fields when the native event provides them:

* `timestamp`
* `eventType` and `eventMessage`
* `messageType`
* `process`, `processID`, `sender`, and `threadID`
* `activityIdentifier`, `parentActivityIdentifier`, and `transitionActivityIdentifier`
* `subsystem`, `category`, and `formatString`
* signpost identifiers, names, types, and scopes

Fields that are unavailable from the native API are omitted. The `messageType` value is normalized to `Default`, `Info`, `Debug`, `Error`, or `Fault`. Native kinds are normalized to the corresponding `logEvent`, `signpostEvent`, `activityCreateEvent`, `activityTransitionEvent`, `lossEvent`, or `stateEvent` values.


## Cursor and deduplication [_cursor_and_deduplication]

The input persists a versioned cursor through Filebeat acknowledgements. It contains a microsecond high-water mark, a hash of the source configuration, and a capped multiset of up to 100,000 recent SHA-256 event IDs. The multiset handles the five-second snapshot overlap and identical events without dropping distinct records. A configuration change starts a new source position. Cursors advance only after the corresponding event is acknowledged.

Existing timestamp-only cursors are migrated automatically. Because they do not contain event IDs, the first native run can replay events in the five-second overlap; later restarts use the event-ID multiset for deduplication.


## Common options [filebeat-input-unifiedlogs-common-options]

The following configuration options are supported by all inputs.


#### `enabled` [_enabled_28]

Use the `enabled` option to enable and disable inputs. By default, enabled is set to true.


#### `tags` [_tags_27]

A list of tags that Filebeat includes in the `tags` field of each published event. Tags make it easy to select specific events in Kibana or apply conditional filtering in Logstash. These tags will be appended to the list of tags specified in the general configuration.

Example:

```yaml
filebeat.inputs:
- type: unifiedlogs
  . . .
  tags: ["json"]
```


#### `fields` [filebeat-input-unifiedlogs-fields]

Optional fields that you can specify to add additional information to the output. For example, you might add fields that you can use for filtering log data. Fields can be scalar values, arrays, dictionaries, or any nested combination of these. By default, the fields that you specify here will be grouped under a `fields` sub-dictionary in the output document. To store the custom fields as top-level fields, set the `fields_under_root` option to true. If a duplicate field is declared in the general configuration, then its value will be overwritten by the value declared here.

```yaml
filebeat.inputs:
- type: unifiedlogs
  . . .
  fields:
    app_id: query_engine_12
```


#### `fields_under_root` [fields-under-root-unifiedlogs]

If this option is set to true, the custom [fields](filebeat-input-unifiedlogs.md#filebeat-input-unifiedlogs-fields) are stored as top-level fields in the output document instead of being grouped under a `fields` sub-dictionary. If the custom field names conflict with other field names added by Filebeat, then the custom fields overwrite the other fields.


#### `processors` [_processors_27]

A list of processors to apply to the input data.

See [Processors](filtering-enhancing-data.md) for information about specifying processors in your config.


#### `pipeline` [_pipeline_27]

The ingest pipeline ID to set for the events generated by this input.

::::{note}
The pipeline ID can also be configured in the Elasticsearch output, but this option usually results in simpler configuration files. If the pipeline is configured both in the input and output, the option from the input is used.
::::


::::{important}
The `pipeline` is always lowercased. If `pipeline: Foo-Bar`, then the pipeline name in {{es}} needs to be defined as `foo-bar`.
::::



#### `keep_null` [_keep_null_27]

If this option is set to true, fields with `null` values will be published in the output document. By default, `keep_null` is set to `false`.


#### `index` [_index_27]

If present, this formatted string overrides the index for events from this input (for elasticsearch outputs), or sets the `raw_index` field of the event’s metadata (for other outputs). This string can only refer to the agent name and version and the event timestamp; for access to dynamic fields, use `output.elasticsearch.index` or a processor.

Example value: `"%{[agent.name]}-myindex-%{+yyyy.MM.dd}"` might expand to `"filebeat-myindex-2019.11.01"`.


#### `publisher_pipeline.disable_host` [_publisher_pipeline_disable_host_27]

By default, all events contain `host.name`. This option can be set to `true` to disable the addition of this field to all events. The default value is `false`.


## Metrics [_metrics_17]

This input exposes metrics under the [HTTP monitoring endpoint](http-endpoint.md). These metrics are exposed under the `/inputs/` path. You must assign a unique `id` to the input to expose metrics.

| Metric | Description |
| --- | --- |
| `errors_total` | Total number of errors. |
| `stream_fallbacks_total` | Number of live stream setups or invalidations that caused a permanent switch to Store polling. |
| `duplicates_dropped_total` | Number of events dropped because their native event ID was already acknowledged or observed in the overlap window. |
