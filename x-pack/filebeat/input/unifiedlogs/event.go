// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin

package unifiedlogs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/elastic-agent-libs/mapstr"
)

const logDateLayout = "2006-01-02 15:04:05.999999-0700"

var timeNow = time.Now

type nativeEventIdentity struct {
	Kind                     nativeEventKind    `json:"kind"`
	Level                    nativeEventLevel   `json:"level"`
	Message                  string             `json:"message"`
	ProcessIdentifier        int64              `json:"process_identifier"`
	Process                  string             `json:"process"`
	Sender                   string             `json:"sender"`
	ThreadIdentifier         uint64             `json:"thread_identifier"`
	ActivityIdentifier       uint64             `json:"activity_identifier"`
	ParentActivityIdentifier uint64             `json:"parent_activity_identifier"`
	Subsystem                string             `json:"subsystem"`
	Category                 string             `json:"category"`
	FormatString             string             `json:"format_string"`
	SignpostIdentifier       uint64             `json:"signpost_identifier"`
	SignpostName             string             `json:"signpost_name"`
	SignpostType             nativeSignpostType `json:"signpost_type"`
}

func includeNativeEvent(cfg commonConfig, event nativeEvent) bool {
	switch event.Kind {
	case nativeKindLog:
		switch event.Level {
		case nativeLevelInfo:
			return cfg.Info
		case nativeLevelDebug:
			return cfg.Debug
		default:
			return true
		}
	case nativeKindSignpost:
		return cfg.Signpost
	case nativeKindActivityCreate,
		nativeKindActivityTransition,
		nativeKindLoss,
		nativeKindState:
		return true
	default:
		return false
	}
}

func normalizeNativeEvent(event nativeEvent) (beat.Event, string, error) {
	eventType, ok := eventTypeName(event.Kind)
	if !ok {
		return beat.Event{}, "", fmt.Errorf("unsupported native event kind %d", event.Kind)
	}

	fields := map[string]any{
		"eventMessage": event.Message,
		"eventType":    eventType,
		"timestamp":    event.Timestamp.In(time.Local).Format(logDateLayout),
	}
	if messageType, ok := messageTypeName(event.Level); ok {
		fields["messageType"] = messageType
	}
	if event.Process != "" {
		fields["process"] = event.Process
	}
	if event.Process != "" || event.ProcessIdentifier != 0 {
		fields["processID"] = event.ProcessIdentifier
	}
	if event.Sender != "" {
		fields["sender"] = event.Sender
	}
	if event.ThreadIdentifier != 0 {
		fields["threadID"] = event.ThreadIdentifier
	}
	if event.ActivityIdentifier != 0 {
		fields["activityIdentifier"] = event.ActivityIdentifier
	}
	if event.ParentActivityIdentifier != 0 {
		fields["parentActivityIdentifier"] = event.ParentActivityIdentifier
	}
	if event.TransitionActivityIdentifier != 0 {
		fields["transitionActivityIdentifier"] = event.TransitionActivityIdentifier
	}
	if event.Subsystem != "" {
		fields["subsystem"] = event.Subsystem
	}
	if event.Category != "" {
		fields["category"] = event.Category
	}
	if event.FormatString != "" {
		fields["formatString"] = event.FormatString
	}
	if event.SignpostIdentifier != 0 {
		fields["signpostIdentifier"] = event.SignpostIdentifier
	}
	if event.SignpostName != "" {
		fields["signpostName"] = event.SignpostName
	}
	if signpostType, ok := signpostTypeName(event.SignpostType); ok {
		fields["signpostType"] = signpostType
	}
	if signpostScope, ok := signpostScopeName(event.SignpostScope); ok {
		fields["signpostScope"] = signpostScope
	}

	message, err := json.Marshal(fields)
	if err != nil {
		return beat.Event{}, "", fmt.Errorf("marshal native unified log event: %w", err)
	}
	id, err := nativeEventID(event)
	if err != nil {
		return beat.Event{}, "", err
	}
	return makeEvent(event.Timestamp, string(message)), id, nil
}

func nativeEventID(event nativeEvent) (string, error) {
	// The live proxy and OSLogStore can assign slightly different wall-clock
	// timestamps to the same record, and the public Store omits private-only
	// fields such as signpost scope. Hash only fields stable across both readers;
	// the cursor's timestamp and ID multiset preserve occurrence counts.
	identity := nativeEventIdentity{
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
	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", fmt.Errorf("marshal native unified log event identity: %w", err)
	}
	sum := sha256.Sum256(encoded)
	id := hex.EncodeToString(sum[:])
	return id, nil
}

func eventTypeName(kind nativeEventKind) (string, bool) {
	switch kind {
	case nativeKindLog:
		return "logEvent", true
	case nativeKindSignpost:
		return "signpostEvent", true
	case nativeKindActivityCreate:
		return "activityCreateEvent", true
	case nativeKindActivityTransition:
		return "activityTransitionEvent", true
	case nativeKindLoss:
		return "lossEvent", true
	case nativeKindState:
		return "stateEvent", true
	default:
		return "", false
	}
}

func messageTypeName(level nativeEventLevel) (string, bool) {
	switch level {
	case nativeLevelDefault:
		return "Default", true
	case nativeLevelInfo:
		return "Info", true
	case nativeLevelDebug:
		return "Debug", true
	case nativeLevelError:
		return "Error", true
	case nativeLevelFault:
		return "Fault", true
	default:
		return "", false
	}
}

func signpostTypeName(signpostType nativeSignpostType) (string, bool) {
	switch signpostType {
	case nativeSignpostEvent:
		return "event", true
	case nativeSignpostIntervalBegin:
		return "begin", true
	case nativeSignpostIntervalEnd:
		return "end", true
	default:
		return "", false
	}
}

func signpostScopeName(scope nativeSignpostScope) (string, bool) {
	switch scope {
	case nativeSignpostScopeThread:
		return "thread", true
	case nativeSignpostScopeProcess:
		return "process", true
	case nativeSignpostScopeSystem:
		return "system", true
	default:
		return "", false
	}
}

func makeEvent(timestamp time.Time, message string) beat.Event {
	fields := mapstr.M{
		"event": mapstr.M{
			"created": timeNow(),
		},
		"message": message,
	}

	return beat.Event{
		Timestamp: timestamp,
		Fields:    fields,
	}
}
