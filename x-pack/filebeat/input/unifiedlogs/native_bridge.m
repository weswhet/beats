// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

#import "native_bridge.h"

#import <Foundation/Foundation.h>
#import <OSLog/OSLog.h>

#import <dispatch/dispatch.h>
#import <dlfcn.h>
#import <errno.h>
#import <math.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <pthread.h>
#import <stdlib.h>
#import <string.h>

// Foundation and OSLog are intentionally not link-time dependencies. Loading
// them with dlopen provides weak-link behavior without relying on cgo linker
// flags that Go rejects, and keeps Filebeat launchable on older macOS releases.

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wformat-nonliteral"

// LoggingSupport is intentionally not linked. The private stream API is
// looked up only after this dlopen succeeds, keeping startup safe when Apple
// removes or changes the private framework.
#define NATIVE_PRIVATE_FRAMEWORK \
	"/System/Library/PrivateFrameworks/LoggingSupport.framework/LoggingSupport"
#define NATIVE_FOUNDATION_FRAMEWORK \
	"/System/Library/Frameworks/Foundation.framework/Foundation"
#define NATIVE_OSLOG_FRAMEWORK \
	"/System/Library/Frameworks/OSLog.framework/OSLog"

static pthread_once_t native_public_frameworks_once = PTHREAD_ONCE_INIT;
static void *native_foundation_framework = NULL;
static void *native_oslog_framework = NULL;
static int native_public_frameworks_status = NATIVE_BRIDGE_UNSUPPORTED;
static const char *native_public_frameworks_error =
	"native public unified log frameworks are unavailable";
static pthread_once_t native_private_framework_once = PTHREAD_ONCE_INIT;
static void *native_private_framework = NULL;

typedef struct native_bridge_cancellation {
	pthread_mutex_t mutex;
	int requested;
} native_bridge_cancellation;

typedef struct native_bridge_stream {
	pthread_mutex_t mutex;
	pthread_cond_t condition;

	native_bridge_event *queue[1024];
	size_t queue_head;
	size_t queue_tail;
	size_t queue_count;

	int invalidated;
	int callback_stopped;
	int freeing;
	uint64_t invalidation_reason;

	unsigned int active_callbacks;

	native_bridge_event_callback callback;
	uintptr_t opaque;
	void *objc_stream;
	dispatch_queue_t callback_queue;
	uint8_t include_info;
	uint8_t include_debug;
	uint8_t include_signpost;
} native_bridge_stream;

native_bridge_cancellation *native_bridge_cancellation_new(void) {
	native_bridge_cancellation *cancellation =
		calloc(1, sizeof(native_bridge_cancellation));
	if (cancellation == NULL) {
		return NULL;
	}
	if (pthread_mutex_init(&cancellation->mutex, NULL) != 0) {
		free(cancellation);
		return NULL;
	}
	return cancellation;
}

void native_bridge_cancellation_request(
	native_bridge_cancellation *cancellation) {
	if (cancellation == NULL) {
		return;
	}
	pthread_mutex_lock(&cancellation->mutex);
	cancellation->requested = 1;
	pthread_mutex_unlock(&cancellation->mutex);
}

static int native_bridge_cancellation_requested(
	native_bridge_cancellation *cancellation) {
	if (cancellation == NULL) {
		return 0;
	}
	pthread_mutex_lock(&cancellation->mutex);
	int requested = cancellation->requested;
	pthread_mutex_unlock(&cancellation->mutex);
	return requested;
}

void native_bridge_cancellation_free(
	native_bridge_cancellation *cancellation) {
	if (cancellation == NULL) {
		return;
	}
	pthread_mutex_destroy(&cancellation->mutex);
	free(cancellation);
}

typedef id (*native_msg_id)(id, SEL);
typedef id (*native_msg_id_id)(id, SEL, id);
typedef id (*native_msg_id_error)(id, SEL, NSError **);
typedef id (*native_msg_id_id_error)(id, SEL, id, NSError **);
typedef id (*native_msg_id_options)(id, SEL, NSUInteger, id, id, NSError **);
typedef void (*native_msg_void_id)(id, SEL, id);
typedef void (*native_msg_void_u64)(id, SEL, uint64_t);
typedef void (*native_msg_void)(id, SEL);
typedef uint64_t (*native_msg_u64)(id, SEL);
typedef int64_t (*native_msg_i64)(id, SEL);
typedef BOOL (*native_msg_bool_class)(id, SEL, Class);

static id native_send_id(id object, SEL selector) {
	return ((native_msg_id)objc_msgSend)(object, selector);
}

static id native_send_id_id(id object, SEL selector, id argument) {
	return ((native_msg_id_id)objc_msgSend)(object, selector, argument);
}

static id native_send_id_error(id object, SEL selector, NSError **error) {
	return ((native_msg_id_error)objc_msgSend)(object, selector, error);
}

static id native_send_id_id_error(id object, SEL selector, id argument,
	NSError **error) {
	return ((native_msg_id_id_error)objc_msgSend)(object, selector, argument,
		error);
}

static id native_send_id_options(id object, SEL selector, NSUInteger options,
	 id position, id predicate, NSError **error) {
	return ((native_msg_id_options)objc_msgSend)(object, selector, options,
		position, predicate, error);
}

static void native_send_void_id(id object, SEL selector, id argument) {
	((native_msg_void_id)objc_msgSend)(object, selector, argument);
}

static void native_send_void_u64(id object, SEL selector, uint64_t value) {
	((native_msg_void_u64)objc_msgSend)(object, selector, value);
}

static void native_send_void(id object, SEL selector) {
	((native_msg_void)objc_msgSend)(object, selector);
}

static uint64_t native_send_u64(id object, SEL selector) {
	return ((native_msg_u64)objc_msgSend)(object, selector);
}

static int64_t native_send_i64(id object, SEL selector) {
	return ((native_msg_i64)objc_msgSend)(object, selector);
}

static BOOL native_is_kind_of_class(id object, Class class) {
	return ((native_msg_bool_class)objc_msgSend)(object,
		@selector(isKindOfClass:), class);
}

static int native_responds_to(id object, SEL selector) {
	return object != nil && [object respondsToSelector:selector];
}

static void native_try_send_void_id(id object, SEL selector, id argument) {
	if (!native_responds_to(object, selector)) {
		return;
	}
	@try {
		native_send_void_id(object, selector, argument);
	} @catch (NSException *exception) {
		(void)exception;
	}
}

static void native_try_send_void(id object, SEL selector) {
	if (!native_responds_to(object, selector)) {
		return;
	}
	@try {
		native_send_void(object, selector);
	} @catch (NSException *exception) {
		(void)exception;
	}
}

static void native_set_error(char **error_out, NSString *message) {
	if (error_out == NULL || *error_out != NULL) {
		return;
	}
	const char *utf8 = message == nil ? "native unified log API error" :
		[message UTF8String];
	if (utf8 != NULL) {
		*error_out = strdup(utf8);
	}
}

static void native_set_error_c(char **error_out, const char *message) {
	if (error_out == NULL || *error_out != NULL || message == NULL) {
		return;
	}
	*error_out = strdup(message);
}

static void native_set_exception_error(char **error_out, NSException *exception) {
	if (exception == nil) {
		native_set_error_c(error_out, "native unified log API raised an exception");
		return;
	}
	NSString *reason = [exception reason];
	if (reason == nil) {
		reason = [exception name];
	}
	native_set_error(error_out, reason);
}

static NSDate *native_date_from_micros(int64_t micros) {
	Class date_class = objc_getClass("NSDate");
	if (date_class == Nil) {
		return nil;
	}
	typedef id (*native_msg_date)(id, SEL, NSTimeInterval);
	return ((native_msg_date)objc_msgSend)(date_class,
		@selector(dateWithTimeIntervalSince1970:),
		(NSTimeInterval)micros / 1000000.0);
}

static id native_new_autorelease_pool(void) {
	Class pool_class = objc_getClass("NSAutoreleasePool");
	if (pool_class == Nil) {
		return nil;
	}
	id pool = native_send_id(pool_class, @selector(alloc));
	return native_send_id(pool, @selector(init));
}

static int64_t native_micros_from_date(NSDate *date) {
	if (date == nil) {
		return 0;
	}
	return (int64_t)llround([date timeIntervalSince1970] * 1000000.0);
}

static char *native_copy_string(id object, SEL selector) {
	if (!native_responds_to(object, selector)) {
		return NULL;
	}
	NSString *value = native_send_id(object, selector);
	Class string_class = objc_getClass("NSString");
	if (value == nil || string_class == Nil ||
		!native_is_kind_of_class(value, string_class)) {
		return NULL;
	}
	const char *utf8 = [value UTF8String];
	return utf8 == NULL ? NULL : strdup(utf8);
}

static char *native_copy_proxy_string(id proxy, SEL selector) {
	// OSLogEventProxy dynamically forwards its event properties and reports
	// false from respondsToSelector:. The live API contract still exposes these
	// selectors, so call them directly and let the callback's exception guard
	// switch the input to Store polling if Apple changes that contract.
	NSString *value = native_send_id(proxy, selector);
	Class string_class = objc_getClass("NSString");
	if (value == nil || string_class == Nil ||
		!native_is_kind_of_class(value, string_class)) {
		return NULL;
	}
	const char *utf8 = [value UTF8String];
	return utf8 == NULL ? NULL : strdup(utf8);
}

static void native_free_event(native_bridge_event *event) {
	if (event == NULL) {
		return;
	}
	free(event->message);
	free(event->process);
	free(event->sender);
	free(event->subsystem);
	free(event->category);
	free(event->format_string);
	free(event->signpost_name);
	free(event);
}

static native_bridge_event *native_alloc_event(void) {
	return calloc(1, sizeof(native_bridge_event));
}

static int native_level_from_public(int64_t level) {
	switch (level) {
	case OSLogEntryLogLevelDebug:
		return NATIVE_BRIDGE_LEVEL_DEBUG;
	case OSLogEntryLogLevelInfo:
		return NATIVE_BRIDGE_LEVEL_INFO;
	case OSLogEntryLogLevelNotice:
		// OSLogStore calls ordinary default-level os_log entries "notice".
		return NATIVE_BRIDGE_LEVEL_DEFAULT;
	case OSLogEntryLogLevelError:
		return NATIVE_BRIDGE_LEVEL_ERROR;
	case OSLogEntryLogLevelFault:
		return NATIVE_BRIDGE_LEVEL_FAULT;
	case OSLogEntryLogLevelUndefined:
		return NATIVE_BRIDGE_LEVEL_DEFAULT;
	default:
		return NATIVE_BRIDGE_LEVEL_UNKNOWN;
	}
}

static int native_level_from_private(uint64_t level) {
	switch (level) {
	case 0:
		return NATIVE_BRIDGE_LEVEL_DEFAULT;
	case 1:
		return NATIVE_BRIDGE_LEVEL_INFO;
	case 2:
		return NATIVE_BRIDGE_LEVEL_DEBUG;
	case 16:
		return NATIVE_BRIDGE_LEVEL_ERROR;
	case 17:
		return NATIVE_BRIDGE_LEVEL_FAULT;
	default:
		return NATIVE_BRIDGE_LEVEL_UNKNOWN;
	}
}

static int native_signpost_type_from_public(int64_t type) {
	switch (type) {
	case OSLogEntrySignpostTypeIntervalBegin:
		return NATIVE_BRIDGE_SIGNPOST_INTERVAL_BEGIN;
	case OSLogEntrySignpostTypeIntervalEnd:
		return NATIVE_BRIDGE_SIGNPOST_INTERVAL_END;
	case OSLogEntrySignpostTypeEvent:
		return NATIVE_BRIDGE_SIGNPOST_EVENT;
	default:
		return NATIVE_BRIDGE_SIGNPOST_UNKNOWN;
	}
}

static int native_signpost_type_from_private(uint64_t type) {
	switch (type) {
	case 0:
		return NATIVE_BRIDGE_SIGNPOST_EVENT;
	case 1:
		return NATIVE_BRIDGE_SIGNPOST_INTERVAL_BEGIN;
	case 2:
		return NATIVE_BRIDGE_SIGNPOST_INTERVAL_END;
	default:
		return NATIVE_BRIDGE_SIGNPOST_UNKNOWN;
	}
}

static int native_signpost_scope_from_private(uint64_t scope) {
	switch (scope) {
	case 64:
		return NATIVE_BRIDGE_SCOPE_THREAD;
	case 128:
		return NATIVE_BRIDGE_SCOPE_PROCESS;
	case 192:
		return NATIVE_BRIDGE_SCOPE_SYSTEM;
	default:
		return NATIVE_BRIDGE_SCOPE_UNKNOWN;
	}
}

static int native_event_allowed(const native_bridge_event *event,
	const native_bridge_query *query) {
	if (event == NULL || query == NULL) {
		return 0;
	}
	if (event->kind == NATIVE_BRIDGE_KIND_SIGNPOST && !query->include_signpost) {
		return 0;
	}
	if (event->level == NATIVE_BRIDGE_LEVEL_DEBUG && !query->include_debug) {
		return 0;
	}
	if (event->level == NATIVE_BRIDGE_LEVEL_INFO && !query->include_info) {
		return 0;
	}
	return 1;
}

static void native_fill_process_fields(native_bridge_event *event, id object) {
	if (event == NULL || object == nil) {
		return;
	}
	event->process = native_copy_string(object, @selector(process));
	event->sender = native_copy_string(object, @selector(sender));
	if (native_responds_to(object, @selector(processIdentifier))) {
		event->process_identifier = native_send_i64(object,
			@selector(processIdentifier));
	}
	if (native_responds_to(object, @selector(threadIdentifier))) {
		event->thread_identifier = native_send_u64(object,
			@selector(threadIdentifier));
	}
	if (native_responds_to(object, @selector(activityIdentifier))) {
		event->activity_identifier = native_send_u64(object,
			@selector(activityIdentifier));
	}
}

static void native_fill_payload_fields(native_bridge_event *event, id object) {
	if (event == NULL || object == nil) {
		return;
	}
	event->subsystem = native_copy_string(object, @selector(subsystem));
	event->category = native_copy_string(object, @selector(category));
	event->format_string = native_copy_string(object, @selector(formatString));
}

static void native_fill_proxy_process_fields(native_bridge_event *event,
	id proxy) {
	event->process = native_copy_proxy_string(proxy,
		sel_registerName("process"));
	event->sender = native_copy_proxy_string(proxy,
		sel_registerName("sender"));
	event->process_identifier = native_send_i64(proxy,
		sel_registerName("processIdentifier"));
	event->thread_identifier = native_send_u64(proxy,
		sel_registerName("threadIdentifier"));
	event->activity_identifier = native_send_u64(proxy,
		sel_registerName("activityIdentifier"));
}

static void native_fill_proxy_payload_fields(native_bridge_event *event,
	id proxy) {
	event->subsystem = native_copy_proxy_string(proxy,
		sel_registerName("subsystem"));
	event->category = native_copy_proxy_string(proxy,
		sel_registerName("category"));
	event->format_string = native_copy_proxy_string(proxy,
		sel_registerName("formatString"));
}

static native_bridge_event *native_event_from_public(id entry,
	const native_bridge_query *query) {
	if (entry == nil || query == NULL) {
		return NULL;
	}
	NSDate *date = native_send_id(entry, @selector(date));
	if (date == nil) {
		return NULL;
	}

	native_bridge_event *event = native_alloc_event();
	if (event == NULL) {
		return NULL;
	}
	event->timestamp_unix_micros = native_micros_from_date(date);
	event->message = native_copy_string(entry, @selector(composedMessage));

	Class log_class = objc_getClass("OSLogEntryLog");
	Class signpost_class = objc_getClass("OSLogEntrySignpost");
	Class activity_class = objc_getClass("OSLogEntryActivity");
	Class boundary_class = objc_getClass("OSLogEntryBoundary");
	if (log_class != Nil && native_is_kind_of_class(entry, log_class)) {
		event->kind = NATIVE_BRIDGE_KIND_LOG;
		event->level = native_level_from_public(native_send_i64(entry,
			@selector(level)));
		native_fill_process_fields(event, entry);
		native_fill_payload_fields(event, entry);
	} else if (signpost_class != Nil && native_is_kind_of_class(entry,
		signpost_class)) {
		event->kind = NATIVE_BRIDGE_KIND_SIGNPOST;
		event->level = NATIVE_BRIDGE_LEVEL_DEFAULT;
		native_fill_process_fields(event, entry);
		native_fill_payload_fields(event, entry);
		if (native_responds_to(entry, @selector(signpostIdentifier))) {
			event->signpost_identifier = native_send_u64(entry,
				@selector(signpostIdentifier));
		}
		event->signpost_name = native_copy_string(entry, @selector(signpostName));
		if (native_responds_to(entry, @selector(signpostType))) {
			event->signpost_type = native_signpost_type_from_public(
				native_send_i64(entry, @selector(signpostType)));
		}
	} else if (activity_class != Nil && native_is_kind_of_class(entry,
		activity_class)) {
		event->kind = NATIVE_BRIDGE_KIND_ACTIVITY_CREATE;
		event->level = NATIVE_BRIDGE_LEVEL_DEFAULT;
		native_fill_process_fields(event, entry);
		if (native_responds_to(entry, @selector(parentActivityIdentifier))) {
			event->parent_activity_identifier = native_send_u64(entry,
				@selector(parentActivityIdentifier));
		}
	} else if (boundary_class != Nil && native_is_kind_of_class(entry,
		boundary_class)) {
		event->kind = NATIVE_BRIDGE_KIND_STATE;
		event->level = NATIVE_BRIDGE_LEVEL_DEFAULT;
	} else {
		// Keep future public subclasses distinct until their semantics can be
		// mapped explicitly. The Go normalization layer discards unknown kinds.
		event->kind = NATIVE_BRIDGE_KIND_UNKNOWN;
		event->level = NATIVE_BRIDGE_LEVEL_UNKNOWN;
	}

	if (!native_event_allowed(event, query)) {
		native_free_event(event);
		return NULL;
	}
	return event;
}

static NSPredicate *native_predicate_from_query(const native_bridge_query *query,
	char **error_out) {
	if (query == NULL || query->predicate == NULL || query->predicate[0] == '\0') {
		return nil;
	}
	Class string_class = objc_getClass("NSString");
	if (string_class == Nil) {
		native_set_error_c(error_out, "Foundation NSString is unavailable");
		return nil;
	}
	typedef id (*native_msg_string)(id, SEL, const char *);
	NSString *format = ((native_msg_string)objc_msgSend)(string_class,
		@selector(stringWithUTF8String:), query->predicate);
	if (format == nil) {
		native_set_error_c(error_out, "native predicate is not valid UTF-8");
		return nil;
	}
	@try {
		Class predicate_class = objc_getClass("NSPredicate");
		Class array_class = objc_getClass("NSArray");
		SEL predicate_selector =
			@selector(predicateWithFormat:argumentArray:);
		if (predicate_class == Nil || array_class == Nil ||
			!class_respondsToSelector(object_getClass(predicate_class),
				predicate_selector)) {
			native_set_error_c(error_out, "Foundation NSPredicate is unavailable");
			return nil;
		}
		NSArray *arguments = native_send_id(array_class, @selector(array));
		typedef id (*native_msg_predicate)(id, SEL, NSString *, NSArray *);
		id predicate = ((native_msg_predicate)objc_msgSend)(predicate_class,
			predicate_selector, format, arguments);
		return predicate == nil ? nil : native_send_id(predicate,
			@selector(retain));
	} @catch (NSException *exception) {
		native_set_exception_error(error_out, exception);
		return nil;
	}
}

static int native_public_store(id *store_out, const native_bridge_query *query,
	char **error_out) {
	if (store_out == NULL || query == NULL) {
		native_set_error_c(error_out, "native OSLogStore query is nil");
		return NATIVE_BRIDGE_ERROR;
	}
	Class store_class = objc_getClass("OSLogStore");
	if (store_class == Nil) {
		native_set_error_c(error_out, "OSLogStore is unavailable (requires macOS 10.15 or newer)");
		return NATIVE_BRIDGE_UNSUPPORTED;
	}

	NSError *error = nil;
	id store = nil;
	@try {
		if (query->archive_file != NULL && query->archive_file[0] != '\0') {
			SEL selector = @selector(storeWithURL:error:);
			if (!class_respondsToSelector(object_getClass(store_class), selector)) {
				native_set_error_c(error_out, "OSLogStore archive API is unavailable");
				return NATIVE_BRIDGE_UNSUPPORTED;
			}
			Class string_class = objc_getClass("NSString");
			Class url_class = objc_getClass("NSURL");
			if (string_class == Nil || url_class == Nil) {
				native_set_error_c(error_out, "Foundation URL APIs are unavailable");
				return NATIVE_BRIDGE_UNSUPPORTED;
			}
			typedef id (*native_msg_string)(id, SEL, const char *);
			NSString *path = ((native_msg_string)objc_msgSend)(string_class,
				@selector(stringWithUTF8String:), query->archive_file);
			typedef id (*native_msg_url)(id, SEL, id);
			NSURL *url = ((native_msg_url)objc_msgSend)(url_class,
				@selector(fileURLWithPath:), path);
			store = native_send_id_id_error(store_class, selector, url, &error);
		} else {
			SEL selector = @selector(localStoreAndReturnError:);
			if (!class_respondsToSelector(object_getClass(store_class), selector)) {
				native_set_error_c(error_out, "OSLogStore local API is unavailable");
				return NATIVE_BRIDGE_UNSUPPORTED;
			}
			store = native_send_id_error(store_class, selector, &error);
		}
	} @catch (NSException *exception) {
		native_set_exception_error(error_out, exception);
		return NATIVE_BRIDGE_ERROR;
	}

	if (store == nil) {
		native_set_error(error_out, [error localizedDescription]);
		return NATIVE_BRIDGE_ERROR;
	}
	*store_out = store;
	return NATIVE_BRIDGE_OK;
}

static void native_initialize_public_frameworks(void) {
	native_foundation_framework = dlopen(NATIVE_FOUNDATION_FRAMEWORK,
		RTLD_LAZY | RTLD_LOCAL);
	if (native_foundation_framework == NULL) {
		native_public_frameworks_error =
			"Foundation framework is unavailable (requires macOS 10.15 or newer)";
		return;
	}
	native_oslog_framework = dlopen(NATIVE_OSLOG_FRAMEWORK,
		RTLD_LAZY | RTLD_LOCAL);
	if (native_oslog_framework == NULL) {
		native_public_frameworks_error =
			"OSLog framework is unavailable (requires macOS 10.15 or newer)";
		dlclose(native_foundation_framework);
		native_foundation_framework = NULL;
		return;
	}
	native_public_frameworks_status = NATIVE_BRIDGE_OK;
}

static int native_load_public_frameworks(char **error_out) {
	if (pthread_once(&native_public_frameworks_once,
		native_initialize_public_frameworks) != 0) {
		native_set_error_c(error_out,
			"could not initialize native public unified log frameworks");
		return NATIVE_BRIDGE_ERROR;
	}
	if (native_public_frameworks_status != NATIVE_BRIDGE_OK) {
		native_set_error_c(error_out, native_public_frameworks_error);
	}
	return native_public_frameworks_status;
}

int native_bridge_read_store(const native_bridge_query *query,
	native_bridge_event_callback callback, uintptr_t opaque,
	native_bridge_cancellation *cancellation, char **error_out) {
	if (error_out != NULL) {
		*error_out = NULL;
	}
	if (query == NULL || callback == NULL) {
		native_set_error_c(error_out, "native OSLogStore query or callback is nil");
		return NATIVE_BRIDGE_ERROR;
	}
	if (native_bridge_cancellation_requested(cancellation)) {
		return NATIVE_BRIDGE_STOPPED;
	}

	int status = NATIVE_BRIDGE_ERROR;
	id store = nil;
	status = native_load_public_frameworks(error_out);
	if (status != NATIVE_BRIDGE_OK) {
		return status;
	}
	id pool = native_new_autorelease_pool();
	if (pool == nil) {
		native_set_error_c(error_out, "Foundation autorelease pools are unavailable");
		return NATIVE_BRIDGE_UNSUPPORTED;
	}
	NSPredicate *predicate = nil;
	@try {
		do {
			status = native_public_store(&store, query, error_out);
			if (status != NATIVE_BRIDGE_OK) {
				break;
			}

			NSDate *start_date = query->has_start ?
				native_date_from_micros(query->start_unix_micros) : nil;
			NSDate *end_date = query->has_end ?
				native_date_from_micros(query->end_unix_micros) : nil;
			OSLogPosition *position = nil;
			if (start_date != nil) {
				// OSLogPosition is inclusive. Move one millisecond earlier so an
				// event exactly at the requested start cannot be lost.
				NSDate *position_date = [start_date dateByAddingTimeInterval:-0.001];
				position = native_send_id_id(store, @selector(positionWithDate:),
					position_date);
			}
			predicate = native_predicate_from_query(query, error_out);
			if (query->predicate != NULL && query->predicate[0] != '\0' &&
				predicate == nil) {
				status = NATIVE_BRIDGE_ERROR;
				break;
			}

			NSError *error = nil;
			SEL enumerator_selector = @selector(entriesEnumeratorWithOptions:position:predicate:error:);
			if (!native_responds_to(store, enumerator_selector)) {
				native_set_error_c(error_out, "OSLogStore enumeration API is unavailable");
				status = NATIVE_BRIDGE_UNSUPPORTED;
				break;
			}
			id enumerator = native_send_id_options(store, enumerator_selector, 0,
				position, predicate, &error);
			if (enumerator == nil) {
				native_set_error(error_out, [error localizedDescription]);
				status = NATIVE_BRIDGE_ERROR;
				break;
			}
			SEL next_selector = @selector(nextObject);
			if (!native_responds_to(enumerator, next_selector)) {
				native_set_error_c(error_out,
					"OSLogStore returned an incompatible entries enumerator");
				status = NATIVE_BRIDGE_UNSUPPORTED;
				break;
			}

			status = NATIVE_BRIDGE_OK;
			for (;;) {
				if (native_bridge_cancellation_requested(cancellation)) {
					status = NATIVE_BRIDGE_STOPPED;
					break;
				}
				id entry_pool = native_new_autorelease_pool();
				id entry = native_send_id(enumerator, next_selector);
				if (entry == nil) {
					[entry_pool drain];
					break;
				}
				if ((start_date != nil || end_date != nil) &&
					native_responds_to(entry, @selector(date))) {
					NSDate *date = native_send_id(entry, @selector(date));
					if (start_date != nil &&
						[date compare:start_date] == NSOrderedAscending) {
						[entry_pool drain];
						continue;
					}
					if (end_date != nil &&
						[date compare:end_date] == NSOrderedDescending) {
						[entry_pool drain];
						break;
					}
				}
				native_bridge_event *event = native_event_from_public(entry, query);
				if (event != NULL) {
					int callback_status = callback(opaque, event);
					native_free_event(event);
					if (callback_status != 0) {
						status = NATIVE_BRIDGE_STOPPED;
						[entry_pool drain];
						break;
					}
				}
				[entry_pool drain];
			}
		} while (0);
	} @catch (NSException *exception) {
		native_set_exception_error(error_out, exception);
		status = NATIVE_BRIDGE_ERROR;
	}
	if (predicate != nil) {
		[predicate release];
	}
	[pool drain];
	return status;
}

// ---- Private LoggingSupport event stream ---------------------------------

static void native_initialize_private_framework(void) {
	native_private_framework = dlopen(NATIVE_PRIVATE_FRAMEWORK,
		RTLD_LAZY | RTLD_LOCAL);
}

static void *native_load_private_framework(char **error_out) {
	if (pthread_once(&native_private_framework_once,
		native_initialize_private_framework) != 0) {
		native_set_error_c(error_out,
			"could not initialize the LoggingSupport private framework");
		return NULL;
	}
	if (native_private_framework == NULL) {
		native_set_error_c(error_out,
			"LoggingSupport private framework is unavailable");
	}
	return native_private_framework;
}

static Class native_private_class(void *framework, const char *name) {
	if (framework == NULL || name == NULL) {
		return Nil;
	}
	// Classes in the dyld shared cache are registered by dlopen but their class
	// symbols are not necessarily visible through dlsym on the returned handle.
	// Resolve through the Objective-C runtime after confirming the framework is
	// loaded, without introducing a private link-time dependency.
	return objc_getClass(name);
}

static id native_private_live_source(void *framework, char **error_out) {
	Class store_class = native_private_class(framework, "OSLogEventLiveStore");
	if (store_class == Nil) {
		native_set_error_c(error_out,
			"LoggingSupport OSLogEventLiveStore is unavailable");
		return nil;
	}
	SEL local_selector = sel_registerName("liveLocalStore");
	if (!class_respondsToSelector(object_getClass(store_class), local_selector)) {
		native_set_error_c(error_out,
			"LoggingSupport liveLocalStore selector is unavailable");
		return nil;
	}
	return native_send_id(store_class, local_selector);
}

static id native_private_live_stream_init(void *framework, id source,
	char **error_out) {
	Class stream_class = native_private_class(framework,
		"OSLogEventLiveStream");
	if (stream_class == Nil) {
		native_set_error_c(error_out,
			"LoggingSupport OSLogEventLiveStream is unavailable");
		return nil;
	}
	SEL init_selector = sel_registerName("initWithLiveSource:");
	if (!class_respondsToSelector(stream_class, init_selector)) {
		native_set_error_c(error_out, "LoggingSupport initWithLiveSource: selector is unavailable");
		return nil;
	}
	id stream = native_send_id_id([stream_class alloc], init_selector, source);
	if (stream == nil) {
		native_set_error_c(error_out,
			"LoggingSupport could not create a live event stream");
	}
	return stream;
}

static int native_stream_callback_enter(native_bridge_stream *stream) {
	pthread_mutex_lock(&stream->mutex);
	if (stream->freeing) {
		pthread_mutex_unlock(&stream->mutex);
		return 0;
	}
	stream->active_callbacks++;
	pthread_mutex_unlock(&stream->mutex);
	return 1;
}

static void native_stream_callback_leave(native_bridge_stream *stream) {
	pthread_mutex_lock(&stream->mutex);
	if (stream->active_callbacks > 0) {
		stream->active_callbacks--;
	}
	pthread_cond_broadcast(&stream->condition);
	pthread_mutex_unlock(&stream->mutex);
}

static void native_stream_mark_invalidated(native_bridge_stream *stream,
	uint64_t reason) {
	if (stream == NULL) {
		return;
	}
	pthread_mutex_lock(&stream->mutex);
	if (!stream->invalidated) {
		stream->invalidated = 1;
		stream->invalidation_reason = reason;
	}
	pthread_cond_broadcast(&stream->condition);
	pthread_mutex_unlock(&stream->mutex);
}

static int native_stream_enqueue(native_bridge_stream *stream,
	native_bridge_event *event) {
	if (stream == NULL || event == NULL) {
		return 0;
	}
	pthread_mutex_lock(&stream->mutex);
	if (stream->invalidated || stream->queue_count >= 1024) {
		pthread_mutex_unlock(&stream->mutex);
		return 0;
	}
	stream->queue[stream->queue_tail] = event;
	stream->queue_tail = (stream->queue_tail + 1) % 1024;
	stream->queue_count++;
	pthread_cond_signal(&stream->condition);
	pthread_mutex_unlock(&stream->mutex);
	return 1;
}

static native_bridge_event *native_stream_dequeue(native_bridge_stream *stream) {
	if (stream == NULL || stream->queue_count == 0) {
		return NULL;
	}
	native_bridge_event *event = stream->queue[stream->queue_head];
	stream->queue[stream->queue_head] = NULL;
	stream->queue_head = (stream->queue_head + 1) % 1024;
	stream->queue_count--;
	return event;
}

static native_bridge_event *native_event_from_private(id proxy,
	const native_bridge_query *query) {
	if (proxy == nil || query == NULL) {
		return NULL;
	}
	native_bridge_event *event = native_alloc_event();
	if (event == NULL) {
		return NULL;
	}
	@try {
		NSDate *date = native_send_id(proxy, sel_registerName("date"));
		if (date == nil) {
			native_free_event(event);
			return NULL;
		}
		event->timestamp_unix_micros = native_micros_from_date(date);
		event->message = native_copy_proxy_string(proxy,
			sel_registerName("composedMessage"));
		uint64_t type = native_send_u64(proxy, sel_registerName("type"));
		switch (type) {
		case 1024: // OSLogEventTypeLogMessage
		case 1152: // OSActivityEventTypeLegacyLogMessage
		case 768:  // OSActivityEventTypeTraceMessage
			event->kind = NATIVE_BRIDGE_KIND_LOG;
			break;
		case 1536: // OSLogEventTypeSignpost
			event->kind = NATIVE_BRIDGE_KIND_SIGNPOST;
			break;
		case 513: // OSLogEventTypeActivityCreate
			event->kind = NATIVE_BRIDGE_KIND_ACTIVITY_CREATE;
			break;
		case 514: // OSLogEventTypeActivityTransition
			event->kind = NATIVE_BRIDGE_KIND_ACTIVITY_TRANSITION;
			break;
		case 1792: // OSLogEventTypeLoss
			event->kind = NATIVE_BRIDGE_KIND_LOSS;
			break;
		case 2560: // OSLogEventTypeStatedump
			event->kind = NATIVE_BRIDGE_KIND_STATE;
			break;
		default:
			event->kind = NATIVE_BRIDGE_KIND_UNKNOWN;
			break;
		}
		event->level = native_level_from_private(
			native_send_u64(proxy, sel_registerName("logType")));
		native_fill_proxy_process_fields(event, proxy);
		native_fill_proxy_payload_fields(event, proxy);
		if (event->kind == NATIVE_BRIDGE_KIND_ACTIVITY_CREATE ||
			event->kind == NATIVE_BRIDGE_KIND_ACTIVITY_TRANSITION) {
			event->parent_activity_identifier = native_send_u64(proxy,
				sel_registerName("parentActivityIdentifier"));
			if (event->kind == NATIVE_BRIDGE_KIND_ACTIVITY_TRANSITION) {
				event->transition_activity_identifier = native_send_u64(proxy,
					sel_registerName("transitionActivityIdentifier"));
			}
		}
		if (event->kind == NATIVE_BRIDGE_KIND_SIGNPOST) {
			event->signpost_identifier = native_send_u64(proxy,
				sel_registerName("signpostIdentifier"));
			event->signpost_name = native_copy_proxy_string(proxy,
				sel_registerName("signpostName"));
			event->signpost_type = native_signpost_type_from_private(
				native_send_u64(proxy, sel_registerName("signpostType")));
			event->signpost_scope = native_signpost_scope_from_private(
				native_send_u64(proxy, sel_registerName("signpostScope")));
		}
		if (!native_event_allowed(event, query)) {
			native_free_event(event);
			return NULL;
		}
		return event;
	} @catch (NSException *exception) {
		(void)exception;
		native_free_event(event);
		@throw;
	}
}

static void native_private_event_handler(native_bridge_stream *stream, id proxy) {
	if (!native_stream_callback_enter(stream)) {
		return;
	}
	id pool = native_new_autorelease_pool();
	if (pool == nil) {
		native_stream_mark_invalidated(stream,
			NATIVE_BRIDGE_INVALIDATION_INITIALIZATION_FAILURE);
		native_stream_callback_leave(stream);
		return;
	}
	native_bridge_query filter_query = {0};
	filter_query.include_info = stream->include_info;
	filter_query.include_debug = stream->include_debug;
	filter_query.include_signpost = stream->include_signpost;
	native_bridge_event *event = NULL;
	@try {
		event = native_event_from_private(proxy, &filter_query);
	} @catch (NSException *exception) {
		(void)exception;
		native_stream_mark_invalidated(stream,
			NATIVE_BRIDGE_INVALIDATION_UNSUPPORTED);
	}
	// The query's predicate is owned by the stream object. Level and signpost
	// filtering is repeated here after private values have been normalized.
	// Private callbacks never retain Go memory, so this handler can safely finish
	// before the consumer runs.
	if (event != NULL && !native_stream_enqueue(stream, event)) {
		native_free_event(event);
		native_stream_mark_invalidated(stream,
			NATIVE_BRIDGE_INVALIDATION_BACKLOGGED);
	}
	[pool drain];
	native_stream_callback_leave(stream);
}

static void native_private_invalidation_handler(native_bridge_stream *stream,
	uint64_t reason, id position) {
	(void)position;
	if (!native_stream_callback_enter(stream)) {
		return;
	}
	native_stream_mark_invalidated(stream, reason);
	native_stream_callback_leave(stream);
}

static void native_private_dropped_event_handler(
	native_bridge_stream *stream, id context) {
	(void)context;
	if (!native_stream_callback_enter(stream)) {
		return;
	}
	// Store polling with overlap is the lossless recovery path when the private
	// live stream reports that events were dropped.
	native_stream_mark_invalidated(stream,
		NATIVE_BRIDGE_INVALIDATION_BACKLOGGED);
	native_stream_callback_leave(stream);
}

// The block wrappers carry only a C heap pointer. They do not capture a Go
// pointer or a Go closure; the integer opaque handle is consumed later by the
// synchronous native_bridge_stream_run call.
static void native_stream_install_handlers(native_bridge_stream *stream,
	id objc_stream) {
	SEL event_selector = sel_registerName("setEventHandler:");
	SEL invalidation_selector = sel_registerName("setInvalidationHandler:");
	SEL dropped_selector = sel_registerName("setDroppedEventHandler:");
	void (^event_handler)(id) = ^(id proxy) {
		native_private_event_handler(stream, proxy);
	};
	void (^invalidation_handler)(uint64_t, id) = ^(uint64_t reason, id position) {
		native_private_invalidation_handler(stream, reason, position);
	};
	void (^dropped_handler)(id) = ^(id context) {
		native_private_dropped_event_handler(stream, context);
	};
	native_send_void_id(objc_stream, event_selector, event_handler);
	native_send_void_id(objc_stream, invalidation_selector, invalidation_handler);
	if (native_responds_to(objc_stream, dropped_selector)) {
		native_send_void_id(objc_stream, dropped_selector, dropped_handler);
	}
}

static void native_stream_dispose(native_bridge_stream *stream) {
	if (stream == NULL) {
		return;
	}

	pthread_mutex_lock(&stream->mutex);
	stream->freeing = 1;
	stream->invalidated = 1;
	if (stream->invalidation_reason == 0) {
		stream->invalidation_reason = NATIVE_BRIDGE_INVALIDATION_BY_REQUEST;
	}
	id objc_stream = (id)stream->objc_stream;
	dispatch_queue_t callback_queue = stream->callback_queue;
	stream->objc_stream = NULL;
	stream->callback_queue = NULL;
	pthread_cond_broadcast(&stream->condition);
	pthread_mutex_unlock(&stream->mutex);

	if (objc_stream != nil) {
		// Clear copied blocks before invalidating. A block already executing is
		// drained by the stream's serial queue below.
		native_try_send_void_id(objc_stream,
			sel_registerName("setEventHandler:"), nil);
		native_try_send_void_id(objc_stream,
			sel_registerName("setInvalidationHandler:"), nil);
		native_try_send_void_id(objc_stream,
			sel_registerName("setDroppedEventHandler:"), nil);
		native_try_send_void(objc_stream, sel_registerName("invalidate"));
	}
	if (callback_queue != NULL) {
		dispatch_sync(callback_queue, ^{});
	}

	pthread_mutex_lock(&stream->mutex);
	while (stream->active_callbacks != 0) {
		pthread_cond_wait(&stream->condition, &stream->mutex);
	}
	pthread_mutex_unlock(&stream->mutex);

	if (objc_stream != nil) {
		[objc_stream release];
	}
	if (callback_queue != NULL) {
		dispatch_release(callback_queue);
	}
	for (size_t index = 0; index < 1024; index++) {
		native_free_event(stream->queue[index]);
	}
	pthread_cond_destroy(&stream->condition);
	pthread_mutex_destroy(&stream->mutex);
	free(stream);
}

static int native_private_prepare(id source, id *prepared_source_out,
	native_bridge_cancellation *cancellation, char **error_out) {
	SEL prepare_selector = sel_registerName("prepareWithCompletionHandler:");
	if (!native_responds_to(source, prepare_selector)) {
		native_set_error_c(error_out, "LoggingSupport prepareWithCompletionHandler: is unavailable");
		return NATIVE_BRIDGE_UNSUPPORTED;
	}
	// The completion handler has (preparedSource, error) arguments according to
	// BridgeSupport. Start uses a semaphore so setup errors are returned before
	// the Go Stream call begins pumping events.
	dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
	__block id prepared_source = nil;
	__block id prepare_error = nil;
	void (^completion)(id, id) = ^(id prepared, id error) {
		prepared_source = [prepared retain];
		prepare_error = [error retain];
		dispatch_semaphore_signal(semaphore);
	};
	native_send_void_id(source, prepare_selector, completion);
	int completed = 0;
	for (int attempt = 0; attempt < 150; attempt++) {
		if (native_bridge_cancellation_requested(cancellation)) {
			native_set_error_c(error_out,
				"LoggingSupport source preparation was canceled");
			return NATIVE_BRIDGE_STOPPED;
		}
		if (dispatch_semaphore_wait(semaphore,
			dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC / 10)) == 0) {
			completed = 1;
			break;
		}
	}
	if (!completed) {
		// The completion handler can still signal after cancellation or timeout,
		// so its captured semaphore must remain valid. Setup is attempted only
		// once before the caller permanently falls back to Store polling.
		if (native_bridge_cancellation_requested(cancellation)) {
			native_set_error_c(error_out,
				"LoggingSupport source preparation was canceled");
			return NATIVE_BRIDGE_STOPPED;
		}
		native_set_error_c(error_out,
			"LoggingSupport source preparation timed out");
		return NATIVE_BRIDGE_FALLBACK;
	}
	dispatch_release(semaphore);
	if (prepare_error != nil) {
		native_set_error(error_out, [prepare_error localizedDescription]);
		[prepared_source release];
		[prepare_error release];
		return NATIVE_BRIDGE_FALLBACK;
	}
	id result = prepared_source == nil ? [source retain] : prepared_source;
	if (prepared_source_out != NULL) {
		// Transfer the callback's retain into the caller's autorelease pool so
		// the prepared source survives callback-thread pool teardown.
		*prepared_source_out = [result autorelease];
	} else {
		[result release];
	}
	return NATIVE_BRIDGE_OK;
}

native_bridge_stream *native_bridge_stream_start(
	const native_bridge_query *query, native_bridge_event_callback callback,
	uintptr_t opaque, native_bridge_cancellation *cancellation, int *status,
	uint64_t *invalidation_reason, char **error_out) {
	if (status != NULL) {
		*status = NATIVE_BRIDGE_ERROR;
	}
	if (invalidation_reason != NULL) {
		*invalidation_reason = 0;
	}
	if (error_out != NULL) {
		*error_out = NULL;
	}
	if (query == NULL || callback == NULL) {
		native_set_error_c(error_out,
			"native OSLogEventLiveStream query or callback is nil");
		return NULL;
	}
	if (native_bridge_cancellation_requested(cancellation)) {
		native_set_error_c(error_out,
			"native OSLogEventLiveStream setup was canceled");
		if (status != NULL) {
			*status = NATIVE_BRIDGE_STOPPED;
		}
		if (invalidation_reason != NULL) {
			*invalidation_reason = NATIVE_BRIDGE_INVALIDATION_BY_REQUEST;
		}
		return NULL;
	}

	void *framework = native_load_private_framework(error_out);
	if (framework == NULL) {
		if (status != NULL) {
			*status = NATIVE_BRIDGE_UNSUPPORTED;
		}
		return NULL;
	}

	native_bridge_stream *stream = calloc(1, sizeof(native_bridge_stream));
	if (stream == NULL) {
		native_set_error_c(error_out, "could not allocate native stream queue");
		return NULL;
	}
	pthread_mutex_init(&stream->mutex, NULL);
	pthread_cond_init(&stream->condition, NULL);
	stream->callback = callback;
	stream->opaque = opaque;
	stream->include_info = query->include_info;
	stream->include_debug = query->include_debug;
	stream->include_signpost = query->include_signpost;

	id pool = native_new_autorelease_pool();
	if (pool == nil) {
		native_set_error_c(error_out,
			"Foundation autorelease pools are unavailable");
		if (status != NULL) {
			*status = NATIVE_BRIDGE_UNSUPPORTED;
		}
		native_stream_dispose(stream);
		return NULL;
	}

	int setup_status = NATIVE_BRIDGE_ERROR;
	id predicate = nil;
	@try {
		id source = native_private_live_source(framework, error_out);
		if (source == nil) {
			setup_status = NATIVE_BRIDGE_UNSUPPORTED;
		} else {
			id prepared_source = nil;
			setup_status = native_private_prepare(source, &prepared_source,
				cancellation, error_out);
			if (setup_status == NATIVE_BRIDGE_OK) {
				id objc_stream = native_private_live_stream_init(framework,
					prepared_source,
					error_out);
				if (objc_stream == nil) {
					setup_status = NATIVE_BRIDGE_FALLBACK;
				} else {
					// Publish the object before invoking any private selector so the
					// centralized failure path can always clear handlers and release it.
					stream->objc_stream = objc_stream;
					SEL filter_selector = sel_registerName("setFilterPredicate:");
					SEL flags_getter = sel_registerName("flags");
					SEL flags_selector = sel_registerName("setFlags:");
					SEL queue_selector = sel_registerName("queue");
					SEL activate_selector = sel_registerName("activate");
					SEL event_selector = sel_registerName("setEventHandler:");
					SEL invalidation_selector = sel_registerName("setInvalidationHandler:");
					SEL invalidate_selector = sel_registerName("invalidate");
					if (!native_responds_to(objc_stream, flags_getter) ||
						!native_responds_to(objc_stream, flags_selector) ||
						!native_responds_to(objc_stream, activate_selector) ||
						!native_responds_to(objc_stream, event_selector) ||
						!native_responds_to(objc_stream, invalidation_selector) ||
						!native_responds_to(objc_stream, invalidate_selector)) {
						native_set_error_c(error_out, "LoggingSupport stream selectors are unavailable");
						setup_status = NATIVE_BRIDGE_UNSUPPORTED;
					} else {
						if (native_responds_to(objc_stream, queue_selector)) {
							dispatch_queue_t callback_queue = (dispatch_queue_t)
								native_send_id(objc_stream, queue_selector);
							if (callback_queue != NULL) {
								dispatch_retain(callback_queue);
								stream->callback_queue = callback_queue;
							}
						}
						uint64_t flags = native_send_u64(objc_stream,
							flags_getter);
						if (query->include_info) {
							flags |= 1; // IncludeInfo.
						}
						if (query->include_debug) {
							flags |= 2; // IncludeDebug.
						}
						if (query->include_signpost) {
							flags |= 32; // IncludeSignposts.
						}
						native_send_void_u64(objc_stream, flags_selector, flags);
						predicate = native_predicate_from_query(query, error_out);
						if (query->predicate != NULL && query->predicate[0] != '\0' &&
							predicate == nil) {
							setup_status = NATIVE_BRIDGE_ERROR;
						} else if (predicate != nil &&
							!native_responds_to(objc_stream, filter_selector)) {
							native_set_error_c(error_out,
								"LoggingSupport live stream predicate selector is unavailable");
							setup_status = NATIVE_BRIDGE_UNSUPPORTED;
						} else {
							if (predicate != nil) {
								native_send_void_id(objc_stream, filter_selector,
									predicate);
							}
							native_stream_install_handlers(stream, objc_stream);
							if (native_bridge_cancellation_requested(cancellation)) {
								native_set_error_c(error_out,
									"native OSLogEventLiveStream setup was canceled");
								setup_status = NATIVE_BRIDGE_STOPPED;
							} else {
								// OSLogEventLiveStream has no date range. Historical and
								// resume data are supplied independently by OSLogStore.
								native_send_void(objc_stream, activate_selector);
								setup_status = NATIVE_BRIDGE_OK;
							}
						}
					}
				}
			}
		}
	} @catch (NSException *exception) {
		native_set_exception_error(error_out, exception);
		setup_status = NATIVE_BRIDGE_FALLBACK;
	}
	if (predicate != nil) {
		[predicate release];
	}
	[pool drain];

	if (setup_status != NATIVE_BRIDGE_OK || stream->objc_stream == NULL) {
		if (status != NULL) {
			*status = setup_status == NATIVE_BRIDGE_UNSUPPORTED ||
				setup_status == NATIVE_BRIDGE_STOPPED ? setup_status :
				NATIVE_BRIDGE_FALLBACK;
		}
		if (setup_status == NATIVE_BRIDGE_STOPPED &&
			invalidation_reason != NULL) {
			*invalidation_reason = NATIVE_BRIDGE_INVALIDATION_BY_REQUEST;
		}
		native_stream_dispose(stream);
		return NULL;
	}

	// The lazily loaded private framework remains open for the process lifetime;
	// Objective-C class registrations cannot safely outlive their image.
	if (status != NULL) {
		*status = NATIVE_BRIDGE_OK;
	}
	return stream;
}

int native_bridge_stream_run(native_bridge_stream *stream, char **error_out,
	uint64_t *invalidation_reason) {
	if (error_out != NULL) {
		*error_out = NULL;
	}
	if (invalidation_reason != NULL) {
		*invalidation_reason = 0;
	}
	if (stream == NULL) {
		native_set_error_c(error_out, "native stream is nil");
		return NATIVE_BRIDGE_ERROR;
	}

	for (;;) {
		pthread_mutex_lock(&stream->mutex);
		while (stream->queue_count == 0 && !stream->invalidated) {
			pthread_cond_wait(&stream->condition, &stream->mutex);
		}
		native_bridge_event *event = native_stream_dequeue(stream);
		int invalidated = stream->invalidated;
		uint64_t reason = stream->invalidation_reason;
		pthread_mutex_unlock(&stream->mutex);

		if (event != NULL) {
			int callback_status = stream->callback(stream->opaque, event);
			native_free_event(event);
			if (callback_status != 0) {
				pthread_mutex_lock(&stream->mutex);
				stream->callback_stopped = 1;
				stream->invalidated = 1;
				stream->invalidation_reason = NATIVE_BRIDGE_INVALIDATION_BY_REQUEST;
				pthread_cond_broadcast(&stream->condition);
				pthread_mutex_unlock(&stream->mutex);
				native_bridge_stream_cancel(stream);
				if (invalidation_reason != NULL) {
					*invalidation_reason = NATIVE_BRIDGE_INVALIDATION_BY_REQUEST;
				}
				return NATIVE_BRIDGE_CALLBACK;
			}
			continue;
		}
		if (invalidated) {
			if (invalidation_reason != NULL) {
				*invalidation_reason = reason;
			}
			if (reason == NATIVE_BRIDGE_INVALIDATION_BY_REQUEST ||
				stream->callback_stopped) {
				return NATIVE_BRIDGE_STOPPED;
			}
			if (reason == 0) {
				native_set_error_c(error_out, "native stream ended without an invalidation reason");
				return NATIVE_BRIDGE_ERROR;
			}
			native_set_error_c(error_out, "native stream invalidated by LoggingSupport");
			return NATIVE_BRIDGE_FALLBACK;
		}
	}
}

void native_bridge_stream_cancel(native_bridge_stream *stream) {
	if (stream == NULL) {
		return;
	}
	pthread_mutex_lock(&stream->mutex);
	if (!stream->invalidated) {
		stream->invalidated = 1;
		stream->invalidation_reason = NATIVE_BRIDGE_INVALIDATION_BY_REQUEST;
	}
	void *objc_stream = stream->objc_stream;
	pthread_cond_broadcast(&stream->condition);
	pthread_mutex_unlock(&stream->mutex);
	if (objc_stream != NULL) {
		native_try_send_void((id)objc_stream, sel_registerName("invalidate"));
	}
}

void native_bridge_stream_free(native_bridge_stream *stream) {
	native_stream_dispose(stream);
}

void native_bridge_free_string(char *value) {
	free(value);
}
