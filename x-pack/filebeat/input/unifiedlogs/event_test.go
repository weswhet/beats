// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin

package unifiedlogs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/mapstr"
)

func TestNativeEventKindNames(t *testing.T) {
	tests := []struct {
		kind nativeEventKind
		name string
		ok   bool
	}{
		{kind: nativeKindUnknown, ok: false},
		{kind: nativeKindLog, name: "logEvent", ok: true},
		{kind: nativeKindSignpost, name: "signpostEvent", ok: true},
		{kind: nativeKindActivityCreate, name: "activityCreateEvent", ok: true},
		{kind: nativeKindActivityTransition, name: "activityTransitionEvent", ok: true},
		{kind: nativeKindLoss, name: "lossEvent", ok: true},
		{kind: nativeKindState, name: "stateEvent", ok: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, ok := eventTypeName(test.kind)
			assert.Equal(t, test.name, name, "native event kind should map to the CLI-compatible event type")
			assert.Equal(t, test.ok, ok, "native event kind mapping should report whether the kind is supported")
		})
	}
}

func TestNativeEventLevelNames(t *testing.T) {
	tests := []struct {
		level nativeEventLevel
		name  string
		ok    bool
	}{
		{level: nativeLevelUnknown, ok: false},
		{level: nativeLevelDefault, name: "Default", ok: true},
		{level: nativeLevelInfo, name: "Info", ok: true},
		{level: nativeLevelDebug, name: "Debug", ok: true},
		{level: nativeLevelError, name: "Error", ok: true},
		{level: nativeLevelFault, name: "Fault", ok: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, ok := messageTypeName(test.level)
			assert.Equal(t, test.name, name, "native event level should map to the CLI-compatible message type")
			assert.Equal(t, test.ok, ok, "native event level mapping should report whether the level is supported")
		})
	}
}

func TestNativeSignpostTypeNames(t *testing.T) {
	tests := []struct {
		signpostType nativeSignpostType
		name         string
		ok           bool
	}{
		{signpostType: nativeSignpostUnknown, ok: false},
		{signpostType: nativeSignpostEvent, name: "event", ok: true},
		{signpostType: nativeSignpostIntervalBegin, name: "begin", ok: true},
		{signpostType: nativeSignpostIntervalEnd, name: "end", ok: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, ok := signpostTypeName(test.signpostType)
			assert.Equal(t, test.name, name, "native signpost type should map to the CLI-compatible name")
			assert.Equal(t, test.ok, ok, "native signpost type mapping should report whether the type is supported")
		})
	}
}

func TestNativeSignpostScopeNames(t *testing.T) {
	tests := []struct {
		scope nativeSignpostScope
		name  string
		ok    bool
	}{
		{scope: nativeSignpostScopeUnknown, ok: false},
		{scope: nativeSignpostScopeThread, name: "thread", ok: true},
		{scope: nativeSignpostScopeProcess, name: "process", ok: true},
		{scope: nativeSignpostScopeSystem, name: "system", ok: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			name, ok := signpostScopeName(test.scope)
			assert.Equal(t, test.name, name, "native signpost scope should map to the CLI-compatible name")
			assert.Equal(t, test.ok, ok, "native signpost scope mapping should report whether the scope is supported")
		})
	}
}

func TestIncludeNativeEvent(t *testing.T) {
	tests := []struct {
		name  string
		cfg   commonConfig
		event nativeEvent
		want  bool
	}{
		{name: "default log level is always included", event: nativeEvent{Kind: nativeKindLog, Level: nativeLevelDefault}, want: true},
		{name: "info is disabled by default", event: nativeEvent{Kind: nativeKindLog, Level: nativeLevelInfo}, want: false},
		{name: "info can be enabled", cfg: commonConfig{Info: true}, event: nativeEvent{Kind: nativeKindLog, Level: nativeLevelInfo}, want: true},
		{name: "debug is disabled by default", event: nativeEvent{Kind: nativeKindLog, Level: nativeLevelDebug}, want: false},
		{name: "debug can be enabled", cfg: commonConfig{Debug: true}, event: nativeEvent{Kind: nativeKindLog, Level: nativeLevelDebug}, want: true},
		{name: "error is always included", event: nativeEvent{Kind: nativeKindLog, Level: nativeLevelError}, want: true},
		{name: "fault is always included", event: nativeEvent{Kind: nativeKindLog, Level: nativeLevelFault}, want: true},
		{name: "unknown log level is retained", event: nativeEvent{Kind: nativeKindLog, Level: nativeLevelUnknown}, want: true},
		{name: "signpost is disabled by default", event: nativeEvent{Kind: nativeKindSignpost}, want: false},
		{name: "signpost can be enabled", cfg: commonConfig{Signpost: true}, event: nativeEvent{Kind: nativeKindSignpost}, want: true},
		{name: "activity create is retained", event: nativeEvent{Kind: nativeKindActivityCreate}, want: true},
		{name: "activity transition is retained", event: nativeEvent{Kind: nativeKindActivityTransition}, want: true},
		{name: "loss is retained", event: nativeEvent{Kind: nativeKindLoss}, want: true},
		{name: "state is retained", event: nativeEvent{Kind: nativeKindState}, want: true},
		{name: "unknown kind is dropped", event: nativeEvent{Kind: nativeKindUnknown}, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, includeNativeEvent(test.cfg, test.event), "native event filtering should honor level and signpost settings")
		})
	}
}

func TestNormalizeNativeEventIncludesAllAvailableFields(t *testing.T) {
	timestamp := time.Date(2025, 1, 2, 3, 4, 5, 123456000, time.FixedZone("test", -7*60*60))
	event := nativeEvent{
		Timestamp:                    timestamp,
		Kind:                         nativeKindSignpost,
		Level:                        nativeLevelFault,
		Message:                      "message",
		ProcessIdentifier:            42,
		Process:                      "worker",
		Sender:                       "sender",
		ThreadIdentifier:             99,
		ActivityIdentifier:           1,
		ParentActivityIdentifier:     2,
		TransitionActivityIdentifier: 3,
		Subsystem:                    "com.example",
		Category:                     "category",
		FormatString:                 "format %{public}s",
		SignpostIdentifier:           88,
		SignpostName:                 "interval",
		SignpostType:                 nativeSignpostIntervalBegin,
		SignpostScope:                nativeSignpostScopeProcess,
	}

	got, id, err := normalizeNativeEvent(event)
	require.NoError(t, err, "a supported native event should normalize successfully")
	message, ok := got.Fields["message"].(string)
	require.True(t, ok, "normalized events should retain their compact JSON in the message field")

	expectedFields := map[string]any{
		"activityIdentifier":           uint64(1),
		"category":                     "category",
		"eventMessage":                 "message",
		"eventType":                    "signpostEvent",
		"formatString":                 "format %{public}s",
		"messageType":                  "Fault",
		"parentActivityIdentifier":     uint64(2),
		"process":                      "worker",
		"processID":                    int64(42),
		"sender":                       "sender",
		"signpostIdentifier":           uint64(88),
		"signpostName":                 "interval",
		"signpostScope":                "process",
		"signpostType":                 "begin",
		"subsystem":                    "com.example",
		"threadID":                     uint64(99),
		"timestamp":                    timestamp.In(time.Local).Format(logDateLayout),
		"transitionActivityIdentifier": uint64(3),
	}
	expectedJSON, err := json.Marshal(expectedFields)
	require.NoError(t, err, "expected native event fields should marshal to JSON")
	assert.Equal(t, string(expectedJSON), message, "native event JSON should be canonical and contain every available field")

	var compact bytes.Buffer
	require.NoError(t, json.Compact(&compact, []byte(message)), "normalized native event JSON should be valid JSON")
	assert.Equal(t, message, compact.String(), "normalized native event JSON should not contain insignificant whitespace")

	expectedIdentity := nativeEventIdentity{
		Kind:                     event.Kind,
		Level:                    event.Level,
		Message:                  event.Message,
		ProcessIdentifier:        event.ProcessIdentifier,
		Process:                  event.Process,
		Sender:                   event.Sender,
		ThreadIdentifier:         event.ThreadIdentifier,
		ActivityIdentifier:       event.ActivityIdentifier,
		ParentActivityIdentifier: event.ParentActivityIdentifier,
		Subsystem:                event.Subsystem,
		Category:                 event.Category,
		FormatString:             event.FormatString,
		SignpostIdentifier:       event.SignpostIdentifier,
		SignpostName:             event.SignpostName,
		SignpostType:             event.SignpostType,
	}
	identityJSON, err := json.Marshal(expectedIdentity)
	require.NoError(t, err, "expected native event identity should marshal to JSON")
	expectedHash := sha256.Sum256(identityJSON)
	assert.Equal(t, hex.EncodeToString(expectedHash[:]), id, "native event IDs should hash fields stable across live and Store readers")
	assert.Equal(t, timestamp, got.Timestamp, "the outer event timestamp should be the native event timestamp")
	created, ok := got.Fields["event"].(mapstr.M)
	require.True(t, ok, "the outer event should retain the event.created object")
	assert.IsType(t, time.Time{}, created["created"], "event.created should be represented as a time.Time")
}

func TestNormalizeNativeEventOmitsUnavailableFields(t *testing.T) {
	timestamp := time.Date(2025, 2, 3, 4, 5, 6, 0, time.UTC)
	event := nativeEvent{
		Timestamp:         timestamp,
		Kind:              nativeKindLog,
		Level:             nativeLevelUnknown,
		Message:           "minimal",
		ProcessIdentifier: 7,
	}

	got, _, err := normalizeNativeEvent(event)
	require.NoError(t, err, "a native event with only required fields should normalize successfully")
	message, ok := got.Fields["message"].(string)
	require.True(t, ok, "normalized events should retain their compact JSON in the message field")

	var fields map[string]any
	require.NoError(t, json.Unmarshal([]byte(message), &fields), "normalized native event JSON should decode")
	assert.Equal(t, "minimal", fields["eventMessage"], "eventMessage should be present when the native message is available")
	assert.Equal(t, "logEvent", fields["eventType"], "eventType should be present for log events")
	assert.Equal(t, timestamp.In(time.Local).Format(logDateLayout), fields["timestamp"], "timestamp should be present for every normalized event")
	assert.Equal(t, float64(7), fields["processID"], "processID should be present even when the process name is unavailable")
	for _, key := range []string{
		"messageType", "process", "sender", "threadID", "activityIdentifier",
		"parentActivityIdentifier", "transitionActivityIdentifier", "subsystem",
		"category", "formatString", "signpostIdentifier", "signpostName",
		"signpostType", "signpostScope",
	} {
		assert.NotContains(t, fields, key, "unavailable native field should be omitted from JSON")
	}
}

func TestNormalizeNativeEventIDIsDeterministic(t *testing.T) {
	event := nativeEvent{
		Timestamp: time.Date(2025, 3, 4, 5, 6, 7, 89000000, time.UTC),
		Kind:      nativeKindLog,
		Level:     nativeLevelInfo,
		Message:   "same event",
	}

	first, firstID, err := normalizeNativeEvent(event)
	require.NoError(t, err, "the first normalization of a supported event should succeed")
	second, secondID, err := normalizeNativeEvent(event)
	require.NoError(t, err, "repeating normalization of the same event should succeed")
	firstMessage, ok := first.Fields["message"].(string)
	require.True(t, ok, "the first normalized event should contain a message")
	secondMessage, ok := second.Fields["message"].(string)
	require.True(t, ok, "the second normalized event should contain a message")
	assert.Equal(t, firstMessage, secondMessage, "identical native events should produce identical canonical JSON")
	assert.Equal(t, firstID, secondID, "identical native events should produce deterministic IDs")

	event.Message = "different event"
	_, changedID, err := normalizeNativeEvent(event)
	require.NoError(t, err, "changing a native event should still normalize successfully")
	assert.NotEqual(t, firstID, changedID, "changing canonical event content should change the event ID")
}

func TestNormalizeNativeEventIDIgnoresReaderSpecificFields(t *testing.T) {
	event := nativeEvent{
		Timestamp:          time.Date(2025, 3, 4, 5, 6, 7, 890123000, time.UTC),
		Kind:               nativeKindSignpost,
		Level:              nativeLevelDefault,
		Message:            "same event",
		ProcessIdentifier:  42,
		Process:            "worker",
		Sender:             "worker",
		ThreadIdentifier:   99,
		Subsystem:          "com.example",
		Category:           "signpost",
		FormatString:       "same event",
		SignpostIdentifier: 7,
		SignpostName:       "interval",
		SignpostType:       nativeSignpostIntervalBegin,
		SignpostScope:      nativeSignpostScopeProcess,
	}

	_, liveID, err := normalizeNativeEvent(event)
	require.NoError(t, err, "the live representation should normalize")
	event.Timestamp = event.Timestamp.Add(-time.Millisecond)
	event.SignpostScope = nativeSignpostScopeUnknown
	_, storeID, err := normalizeNativeEvent(event)
	require.NoError(t, err, "the Store representation should normalize")

	assert.Equal(t, liveID, storeID, "reader-specific timestamp skew and unavailable private fields must not change the event identity")
}

func TestNormalizeNativeEventRejectsUnknownKind(t *testing.T) {
	_, _, err := normalizeNativeEvent(nativeEvent{Kind: nativeKindUnknown})
	require.Error(t, err, "unknown native event kinds should not be emitted")
	assert.Contains(t, err.Error(), "unsupported native event kind", "unknown-kind errors should identify the unsupported event kind")
}
