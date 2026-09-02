// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin

package unifiedlogs

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// nativeReader reads unified log entries through Apple's native APIs.
//
// ReadStore enumerates a fixed OSLogStore snapshot. Stream starts an
// indefinite live stream when the private LoggingSupport API is available.
// Implementations must invoke emit synchronously with a fully-owned event.
type nativeReader interface {
	ReadStore(context.Context, nativeQuery, func(nativeEvent) error) error
	Stream(context.Context, nativeQuery, func(nativeEvent) error) error
}

// nativeQuery is deliberately independent from the input configuration. The
// caller combines predicate and process selectors before crossing the cgo
// boundary so both native readers evaluate the same predicate.
type nativeQuery struct {
	ArchiveFile string
	Start       time.Time
	End         time.Time
	Predicate   string
	Info        bool
	Debug       bool
	Signpost    bool
}

// nativeEventKind is normalized by the adapter. It must not expose the
// private OSActivityEventType values because those values are not stable API.
type nativeEventKind uint8

const (
	nativeKindUnknown nativeEventKind = iota
	nativeKindLog
	nativeKindSignpost
	nativeKindActivityCreate
	nativeKindActivityTransition
	nativeKindLoss
	nativeKindState
)

// nativeEventLevel is the common level vocabulary used by the public and
// private readers. Unknown values remain representable as nativeLevelUnknown.
type nativeEventLevel uint8

const (
	nativeLevelUnknown nativeEventLevel = iota
	nativeLevelDefault
	nativeLevelInfo
	nativeLevelDebug
	nativeLevelError
	nativeLevelFault
)

// nativeSignpostType is normalized across the public OSLogEntrySignpost enum
// and the private OSLogEventProxy enum. The public API uses 1/2/3 while the
// private API uses 1/2/0 for the same values.
type nativeSignpostType uint8

const (
	nativeSignpostUnknown nativeSignpostType = iota
	nativeSignpostEvent
	nativeSignpostIntervalBegin
	nativeSignpostIntervalEnd
)

// nativeSignpostScope is the package-owned representation of the private
// scope bit values (thread, process, and system).
type nativeSignpostScope uint8

const (
	nativeSignpostScopeUnknown nativeSignpostScope = iota
	nativeSignpostScopeThread
	nativeSignpostScopeProcess
	nativeSignpostScopeSystem
)

// nativeEvent contains copies of all data read from an OSLog entry. Numeric
// identifiers are zero when the source does not expose that property.
type nativeEvent struct {
	Timestamp time.Time
	Kind      nativeEventKind
	Level     nativeEventLevel

	Message string

	ProcessIdentifier int64
	Process           string
	Sender            string
	ThreadIdentifier  uint64

	ActivityIdentifier           uint64
	ParentActivityIdentifier     uint64
	TransitionActivityIdentifier uint64

	Subsystem    string
	Category     string
	FormatString string

	SignpostIdentifier uint64
	SignpostName       string
	SignpostType       nativeSignpostType
	SignpostScope      nativeSignpostScope
}

var errNativeReaderUnsupported = errors.New("native unified log reader is unsupported on this system")

// nativeStreamFallbackError marks an OSLogEventLiveStream setup or runtime
// invalidation that requires the caller to permanently use Store polling for
// this process. A requested context cancellation is intentionally not wrapped
// in this error.
type nativeStreamFallbackError struct {
	Reason uint64
	Err    error
}

func (e *nativeStreamFallbackError) Error() string {
	if e == nil {
		return "native unified log stream unavailable"
	}
	if e.Err == nil {
		return fmt.Sprintf("native unified log stream invalidated (reason %d)", e.Reason)
	}
	return fmt.Sprintf("native unified log stream invalidated (reason %d): %v", e.Reason, e.Err)
}

func (e *nativeStreamFallbackError) Unwrap() error { return e.Err }
