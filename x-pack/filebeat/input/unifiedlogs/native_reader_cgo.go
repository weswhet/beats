// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin && cgo

package unifiedlogs

/*
#cgo darwin CFLAGS: -mmacosx-version-min=10.15
#cgo darwin LDFLAGS: -ldl
#include <stdint.h>
#include <stdlib.h>
#include "native_bridge.h"
extern int nativeBridgeEventCallback(uintptr_t opaque,
	native_bridge_event *event);
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"runtime/cgo"
	"sync"
	"time"
	"unsafe"
)

type cgoNativeReader struct{}

func newNativeReader() (nativeReader, error) { return cgoNativeReader{}, nil }

func (cgoNativeReader) ReadStore(ctx context.Context, query nativeQuery, emit func(nativeEvent) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	cQuery, release := makeNativeBridgeQuery(query)
	defer release()

	var callbackErr error
	callback := func(event nativeEvent) error {
		if err := ctx.Err(); err != nil {
			callbackErr = err
			return err
		}
		if emit == nil {
			return nil
		}
		if err := emit(event); err != nil {
			callbackErr = err
			return err
		}
		return nil
	}
	handle := cgo.NewHandle(callback)
	defer handle.Delete()
	cancellation, stopCancellation, err := newNativeBridgeCancellation(ctx)
	if err != nil {
		return err
	}
	defer stopCancellation()

	var errorOut *C.char
	status := C.native_bridge_read_store(
		&cQuery,
		(C.native_bridge_event_callback)(C.nativeBridgeEventCallback),
		C.uintptr_t(handle),
		cancellation,
		&errorOut,
	)
	message := takeNativeBridgeError(errorOut)

	if callbackErr != nil {
		return callbackErr
	}
	if err := ctx.Err(); err != nil && status == C.NATIVE_BRIDGE_STOPPED {
		return err
	}
	if status == C.NATIVE_BRIDGE_OK || status == C.NATIVE_BRIDGE_STOPPED {
		return nil
	}
	if message == "" {
		message = "native OSLogStore enumeration failed"
	}
	if status == C.NATIVE_BRIDGE_UNSUPPORTED {
		return fmt.Errorf("%w: %s", errNativeReaderUnsupported, message)
	}
	return errors.New(message)
}

func (cgoNativeReader) Stream(ctx context.Context, query nativeQuery, emit func(nativeEvent) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	cQuery, release := makeNativeBridgeQuery(query)
	defer release()

	var callbackErr error
	callback := func(event nativeEvent) error {
		if err := ctx.Err(); err != nil {
			callbackErr = err
			return err
		}
		if emit == nil {
			return nil
		}
		if err := emit(event); err != nil {
			callbackErr = err
			return err
		}
		return nil
	}
	handle := cgo.NewHandle(callback)
	defer handle.Delete()
	cancellation, stopCancellation, err := newNativeBridgeCancellation(ctx)
	if err != nil {
		return err
	}

	var (
		status             C.int
		invalidationReason C.uint64_t
		errorOut           *C.char
		stream             *C.native_bridge_stream
	)
	stream = C.native_bridge_stream_start(
		&cQuery,
		(C.native_bridge_event_callback)(C.nativeBridgeEventCallback),
		C.uintptr_t(handle),
		cancellation,
		&status,
		&invalidationReason,
		&errorOut,
	)
	stopCancellation()
	message := takeNativeBridgeError(errorOut)
	if stream == nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		if message == "" {
			message = "native OSLogEventLiveStream setup failed"
		}
		return &nativeStreamFallbackError{
			Reason: uint64(invalidationReason),
			Err:    fmt.Errorf("%s", message),
		}
	}

	// Keep the stream alive while the cancellation goroutine can invalidate it.
	runDone := make(chan struct{})
	cancelDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			C.native_bridge_stream_cancel(stream)
		case <-runDone:
		}
		close(cancelDone)
	}()

	errorOut = nil
	streamStatus := C.native_bridge_stream_run(stream, &errorOut, &invalidationReason)
	message = takeNativeBridgeError(errorOut)
	close(runDone)
	<-cancelDone
	C.native_bridge_stream_free(stream)

	if callbackErr != nil {
		return callbackErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if streamStatus == C.NATIVE_BRIDGE_OK || streamStatus == C.NATIVE_BRIDGE_STOPPED {
		return nil
	}
	if message == "" {
		message = "native OSLogEventLiveStream was invalidated"
	}
	if streamStatus == C.NATIVE_BRIDGE_FALLBACK {
		return &nativeStreamFallbackError{
			Reason: uint64(invalidationReason),
			Err:    errors.New(message),
		}
	}
	return errors.New(message)
}

func newNativeBridgeCancellation(ctx context.Context) (
	*C.native_bridge_cancellation,
	func(),
	error,
) {
	cancellation := C.native_bridge_cancellation_new()
	if cancellation == nil {
		return nil, nil, errors.New("allocate native unified log cancellation state")
	}

	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			C.native_bridge_cancellation_request(cancellation)
		case <-done:
		}
		close(finished)
	}()

	var once sync.Once
	return cancellation, func() {
		once.Do(func() {
			close(done)
			<-finished
			C.native_bridge_cancellation_free(cancellation)
		})
	}, nil
}

func makeNativeBridgeQuery(query nativeQuery) (C.native_bridge_query, func()) {
	var (
		archive   *C.char
		predicate *C.char
	)
	if query.ArchiveFile != "" {
		archive = C.CString(query.ArchiveFile)
	}
	if query.Predicate != "" {
		predicate = C.CString(query.Predicate)
	}

	cQuery := C.native_bridge_query{
		archive_file:     archive,
		predicate:        predicate,
		include_info:     boolToCByte(query.Info),
		include_debug:    boolToCByte(query.Debug),
		include_signpost: boolToCByte(query.Signpost),
	}
	if !query.Start.IsZero() {
		cQuery.has_start = 1
		cQuery.start_unix_micros = C.int64_t(unixMicros(query.Start))
	}
	if !query.End.IsZero() {
		cQuery.has_end = 1
		cQuery.end_unix_micros = C.int64_t(unixMicros(query.End))
	}

	return cQuery, func() {
		if archive != nil {
			C.free(unsafe.Pointer(archive))
		}
		if predicate != nil {
			C.free(unsafe.Pointer(predicate))
		}
	}
}

func boolToCByte(value bool) C.uint8_t {
	if value {
		return 1
	}
	return 0
}

func unixMicros(value time.Time) int64 {
	return value.UnixNano() / int64(time.Microsecond)
}

func takeNativeBridgeError(errorOut *C.char) string {
	if errorOut == nil {
		return ""
	}
	defer C.native_bridge_free_string(errorOut)
	return C.GoString(errorOut)
}

func copyNativeBridgeString(value *C.char) string {
	if value == nil {
		return ""
	}
	return C.GoString(value)
}

// nativeBridgeEventCallback is called by C only while the corresponding
// cgo.Handle is alive. C owns event and string memory until this function
// returns, so conversion here is the ownership boundary.
//
//export nativeBridgeEventCallback
func nativeBridgeEventCallback(opaque C.uintptr_t, event *C.native_bridge_event) C.int {
	if event == nil {
		return 1
	}

	callback, ok := cgo.Handle(uintptr(opaque)).Value().(func(nativeEvent) error)
	if !ok || callback == nil {
		return 1
	}

	native := nativeEvent{
		Timestamp: time.Unix(0, int64(event.timestamp_unix_micros)*int64(time.Microsecond)),
		Kind:      nativeEventKind(event.kind),
		Level:     nativeEventLevel(event.level),
		Message:   copyNativeBridgeString(event.message),

		ProcessIdentifier: int64(event.process_identifier),
		Process:           copyNativeBridgeString(event.process),
		Sender:            copyNativeBridgeString(event.sender),
		ThreadIdentifier:  uint64(event.thread_identifier),

		ActivityIdentifier:           uint64(event.activity_identifier),
		ParentActivityIdentifier:     uint64(event.parent_activity_identifier),
		TransitionActivityIdentifier: uint64(event.transition_activity_identifier),

		Subsystem:    copyNativeBridgeString(event.subsystem),
		Category:     copyNativeBridgeString(event.category),
		FormatString: copyNativeBridgeString(event.format_string),

		SignpostIdentifier: uint64(event.signpost_identifier),
		SignpostName:       copyNativeBridgeString(event.signpost_name),
		SignpostType:       nativeSignpostType(event.signpost_type),
		SignpostScope:      nativeSignpostScope(event.signpost_scope),
	}

	if err := callback(native); err != nil {
		return 1
	}
	return 0
}
