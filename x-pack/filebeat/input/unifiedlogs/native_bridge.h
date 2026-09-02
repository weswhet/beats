// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

#ifndef BEATS_UNIFIEDLOGS_NATIVE_BRIDGE_H
#define BEATS_UNIFIEDLOGS_NATIVE_BRIDGE_H

#include <stdint.h>

// native_bridge_query contains only C-owned values. The Go caller keeps the
// pointed-to strings alive until the synchronous bridge call returns.
typedef struct native_bridge_query {
	const char *archive_file;
	int64_t start_unix_micros;
	int64_t end_unix_micros;
	uint8_t has_start;
	uint8_t has_end;
	const char *predicate;
	uint8_t include_info;
	uint8_t include_debug;
	uint8_t include_signpost;
} native_bridge_query;

// native_bridge_event is allocated by the bridge and freed after the callback
// returns. Every string is a separately allocated UTF-8 copy of the native
// NSString value; no ObjC object crosses the cgo boundary.
typedef struct native_bridge_event {
	int64_t timestamp_unix_micros;
	int32_t kind;
	int32_t level;

	char *message;

	int64_t process_identifier;
	char *process;
	char *sender;
	uint64_t thread_identifier;

	uint64_t activity_identifier;
	uint64_t parent_activity_identifier;
	uint64_t transition_activity_identifier;

	char *subsystem;
	char *category;
	char *format_string;

	uint64_t signpost_identifier;
	char *signpost_name;
	uint64_t signpost_type;
	uint64_t signpost_scope;
} native_bridge_event;

// These values mirror the package-owned Go enums in native_reader.go. They
// are intentionally distinct from Apple's public/private enum values.
enum {
	NATIVE_BRIDGE_KIND_UNKNOWN = 0,
	NATIVE_BRIDGE_KIND_LOG = 1,
	NATIVE_BRIDGE_KIND_SIGNPOST = 2,
	NATIVE_BRIDGE_KIND_ACTIVITY_CREATE = 3,
	NATIVE_BRIDGE_KIND_ACTIVITY_TRANSITION = 4,
	NATIVE_BRIDGE_KIND_LOSS = 5,
	NATIVE_BRIDGE_KIND_STATE = 6,
};

enum {
	NATIVE_BRIDGE_LEVEL_UNKNOWN = 0,
	NATIVE_BRIDGE_LEVEL_DEFAULT = 1,
	NATIVE_BRIDGE_LEVEL_INFO = 2,
	NATIVE_BRIDGE_LEVEL_DEBUG = 3,
	NATIVE_BRIDGE_LEVEL_ERROR = 4,
	NATIVE_BRIDGE_LEVEL_FAULT = 5,
};

enum {
	NATIVE_BRIDGE_SIGNPOST_UNKNOWN = 0,
	NATIVE_BRIDGE_SIGNPOST_EVENT = 1,
	NATIVE_BRIDGE_SIGNPOST_INTERVAL_BEGIN = 2,
	NATIVE_BRIDGE_SIGNPOST_INTERVAL_END = 3,
};

enum {
	NATIVE_BRIDGE_SCOPE_UNKNOWN = 0,
	NATIVE_BRIDGE_SCOPE_THREAD = 1,
	NATIVE_BRIDGE_SCOPE_PROCESS = 2,
	NATIVE_BRIDGE_SCOPE_SYSTEM = 3,
};

typedef int (*native_bridge_event_callback)(uintptr_t opaque,
	const native_bridge_event *event);

// native_bridge_cancellation is C-owned state that can be requested from a Go
// goroutine without retaining a Go pointer in an Objective-C object or block.
typedef struct native_bridge_cancellation native_bridge_cancellation;

native_bridge_cancellation *native_bridge_cancellation_new(void);
void native_bridge_cancellation_request(
	native_bridge_cancellation *cancellation);
void native_bridge_cancellation_free(
	native_bridge_cancellation *cancellation);

enum {
	NATIVE_BRIDGE_OK = 0,
	NATIVE_BRIDGE_STOPPED = 1,
	NATIVE_BRIDGE_ERROR = 2,
	NATIVE_BRIDGE_UNSUPPORTED = 3,
	NATIVE_BRIDGE_FALLBACK = 4,
	NATIVE_BRIDGE_CALLBACK = 5,
};

enum {
	NATIVE_BRIDGE_INVALIDATION_DISCONNECTED = 1,
	NATIVE_BRIDGE_INVALIDATION_BACKLOGGED = 2,
	NATIVE_BRIDGE_INVALIDATION_INVALID_POSITION = 3,
	NATIVE_BRIDGE_INVALIDATION_BY_REQUEST = 4,
	NATIVE_BRIDGE_INVALIDATION_END_OF_STREAM = 5,
	NATIVE_BRIDGE_INVALIDATION_UNSUPPORTED = 6,
	NATIVE_BRIDGE_INVALIDATION_INSUFFICIENT_PERMISSIONS = 7,
	NATIVE_BRIDGE_INVALIDATION_PREDICATE_FAILURE = 8,
	NATIVE_BRIDGE_INVALIDATION_INITIALIZATION_FAILURE = 9,
};

// native_bridge_read_store performs a synchronous fixed-snapshot enumeration.
// error_out, when non-NULL, receives a malloc'ed UTF-8 message owned by the
// caller and released with native_bridge_free_string.
int native_bridge_read_store(const native_bridge_query *query,
	native_bridge_event_callback callback, uintptr_t opaque,
	native_bridge_cancellation *cancellation, char **error_out);

typedef struct native_bridge_stream native_bridge_stream;

// native_bridge_stream_start performs private live API probing, source
// preparation, handler installation, and activation. A NULL result is a setup
// failure; status distinguishes unsupported from other failures.
native_bridge_stream *native_bridge_stream_start(
	const native_bridge_query *query, native_bridge_event_callback callback,
	uintptr_t opaque, native_bridge_cancellation *cancellation, int *status,
	uint64_t *invalidation_reason, char **error_out);

// native_bridge_stream_run pumps the bounded native queue until the stream is
// invalidated or the callback asks it to stop.
int native_bridge_stream_run(native_bridge_stream *stream, char **error_out,
	uint64_t *invalidation_reason);

// Cancellation is safe to call concurrently with native_bridge_stream_run.
void native_bridge_stream_cancel(native_bridge_stream *stream);
void native_bridge_stream_free(native_bridge_stream *stream);

void native_bridge_free_string(char *value);

#endif
