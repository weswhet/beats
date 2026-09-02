// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin

package unifiedlogs

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	inputcursor "github.com/elastic/beats/v7/filebeat/input/v2/input-cursor"
	"github.com/elastic/elastic-agent-libs/logp"
)

const (
	cursorVersion      = 1
	cursorRecentIDCap  = 100_000
	cursorOverlap      = 5 * time.Second
	cursorOverlapMicro = int64(cursorOverlap / time.Microsecond)
)

// cursorState is persisted by the cursor input only after the event carrying it
// is acknowledged. RecentEventIDs is a multiset: equal entries are deliberately
// retained so identical log records can be distinguished across an overlap.
type cursorState struct {
	Version          int           `json:"version"`
	HighWaterMicros  int64         `json:"high_water_mark_micros"`
	SourceConfigHash string        `json:"source_config_hash"`
	RecentEventIDs   []cursorEvent `json:"recent_event_ids,omitempty"`
}

type cursorEvent struct {
	TimestampMicros int64  `json:"timestamp_micros"`
	ID              string `json:"id"`
}

func newCursorState(configHash string) cursorState {
	return cursorState{
		Version:          cursorVersion,
		SourceConfigHash: configHash,
	}
}

func loadCursor(c inputcursor.Cursor, configHash string, log *logp.Logger) (cursorState, error) {
	return loadCursorFrom(c, configHash, log)
}

type cursorUnpacker interface {
	IsNew() bool
	Unpack(any) error
}

func loadCursorFrom(c cursorUnpacker, configHash string, log *logp.Logger) (cursorState, error) {
	if c.IsNew() {
		return newCursorState(configHash), nil
	}

	var state cursorState
	stateErr := c.Unpack(&state)
	if stateErr == nil && state.Version != 0 {
		if err := validateCursorState(state); err != nil {
			return cursorState{}, fmt.Errorf("invalid unified logs cursor: %w", err)
		}
		if state.SourceConfigHash != configHash {
			log.Infof("unified logs configuration changed; resetting the saved cursor")
			return newCursorState(configHash), nil
		}

		state = compactCursorState(state)
		log.Infof("cursor loaded, resuming from: %s", cursorTime(state.HighWaterMicros))
		return state, nil
	}

	// Cursors written by the CLI implementation contain a bare time.Time.
	var legacy time.Time
	legacyErr := c.Unpack(&legacy)
	if legacyErr != nil {
		return cursorState{}, fmt.Errorf(
			"unpack cursor as versioned state or legacy timestamp: %w",
			errors.Join(stateErr, legacyErr),
		)
	}
	if legacy.IsZero() {
		return cursorState{}, errors.New("legacy unified logs cursor contains a zero timestamp")
	}

	state = newCursorState(configHash)
	state.HighWaterMicros = legacy.UnixMicro()
	log.Infof("legacy cursor loaded, resuming with overlap from: %s", cursorTime(state.HighWaterMicros))
	return state, nil
}

func validateCursorState(state cursorState) error {
	if state.Version != cursorVersion {
		return fmt.Errorf("unsupported version %d", state.Version)
	}
	if state.SourceConfigHash == "" {
		return errors.New("source_config_hash is empty")
	}
	if len(state.RecentEventIDs) > cursorRecentIDCap {
		return fmt.Errorf("recent_event_ids contains %d entries, maximum is %d", len(state.RecentEventIDs), cursorRecentIDCap)
	}
	for i, event := range state.RecentEventIDs {
		if len(event.ID) != 64 {
			return fmt.Errorf("recent_event_ids[%d] is not a SHA-256 identifier", i)
		}
		if _, err := hex.DecodeString(event.ID); err != nil {
			return fmt.Errorf("recent_event_ids[%d] is not a SHA-256 identifier: %w", i, err)
		}
	}
	return nil
}

func compactCursorState(state cursorState) cursorState {
	state.Version = cursorVersion
	state.RecentEventIDs = slices.Clone(state.RecentEventIDs)
	slices.SortStableFunc(state.RecentEventIDs, func(a, b cursorEvent) int {
		switch {
		case a.TimestampMicros < b.TimestampMicros:
			return -1
		case a.TimestampMicros > b.TimestampMicros:
			return 1
		default:
			return 0
		}
	})

	cutoff := state.HighWaterMicros - cursorOverlapMicro
	first := 0
	for first < len(state.RecentEventIDs) && state.RecentEventIDs[first].TimestampMicros < cutoff {
		first++
	}
	state.RecentEventIDs = slices.Clone(state.RecentEventIDs[first:])
	if excess := len(state.RecentEventIDs) - cursorRecentIDCap; excess > 0 {
		state.RecentEventIDs = slices.Clone(state.RecentEventIDs[excess:])
	}
	return state
}

func cursorTime(micros int64) time.Time {
	return time.Unix(0, micros*int64(time.Microsecond))
}

type stateTracker struct {
	state  cursorState
	counts map[string]int
}

func newStateTracker(state cursorState) *stateTracker {
	state = compactCursorState(state)
	tracker := &stateTracker{
		state:  state,
		counts: make(map[string]int, len(state.RecentEventIDs)),
	}
	for _, event := range state.RecentEventIDs {
		tracker.counts[event.ID]++
	}
	return tracker
}

func (t *stateTracker) highWater() int64 {
	return t.state.HighWaterMicros
}

func (t *stateTracker) count(id string) int {
	return t.counts[id]
}

func (t *stateTracker) add(timestampMicros int64, id string) {
	if timestampMicros > t.state.HighWaterMicros {
		t.state.HighWaterMicros = timestampMicros
		t.evictBefore(t.state.HighWaterMicros - cursorOverlapMicro)
	}

	if timestampMicros < t.state.HighWaterMicros-cursorOverlapMicro {
		return
	}
	event := cursorEvent{
		TimestampMicros: timestampMicros,
		ID:              id,
	}
	insertAt := len(t.state.RecentEventIDs)
	if insertAt > 0 && timestampMicros < t.state.RecentEventIDs[insertAt-1].TimestampMicros {
		insertAt = sort.Search(insertAt, func(i int) bool {
			return t.state.RecentEventIDs[i].TimestampMicros > timestampMicros
		})
	}
	t.state.RecentEventIDs = append(t.state.RecentEventIDs, cursorEvent{})
	copy(t.state.RecentEventIDs[insertAt+1:], t.state.RecentEventIDs[insertAt:])
	t.state.RecentEventIDs[insertAt] = event
	t.counts[id]++

	if excess := len(t.state.RecentEventIDs) - cursorRecentIDCap; excess > 0 {
		t.removePrefix(excess)
	}
}

func (t *stateTracker) evictBefore(cutoff int64) {
	first := 0
	for first < len(t.state.RecentEventIDs) && t.state.RecentEventIDs[first].TimestampMicros < cutoff {
		first++
	}
	t.removePrefix(first)
}

func (t *stateTracker) removePrefix(n int) {
	for _, event := range t.state.RecentEventIDs[:n] {
		t.counts[event.ID]--
		if t.counts[event.ID] == 0 {
			delete(t.counts, event.ID)
		}
	}
	copy(t.state.RecentEventIDs, t.state.RecentEventIDs[n:])
	t.state.RecentEventIDs = t.state.RecentEventIDs[:len(t.state.RecentEventIDs)-n]
}

func (t *stateTracker) merge(other *stateTracker) {
	merged := cursorState{
		Version:          cursorVersion,
		HighWaterMicros:  max(t.state.HighWaterMicros, other.state.HighWaterMicros),
		SourceConfigHash: t.state.SourceConfigHash,
		RecentEventIDs: append(
			slices.Clone(t.state.RecentEventIDs),
			other.state.RecentEventIDs...,
		),
	}
	*t = *newStateTracker(compactCursorState(merged))
}

func (t *stateTracker) snapshot() cursorState {
	state := t.state
	state.RecentEventIDs = slices.Clone(t.state.RecentEventIDs)
	return state
}

type cursorPath uint8

const (
	cursorPathHistory cursorPath = iota
	cursorPathLive
)

type dedupeSession struct {
	seen map[string]int
}

func newDedupeSession() *dedupeSession {
	return &dedupeSession{seen: make(map[string]int)}
}

// cursorCoordinator atomically deduplicates overlapping native reads and
// assigns immutable cursor snapshots to events. Live events intentionally carry
// no cursor while history is running, so acknowledging a newer live event can
// never skip an older, unacknowledged backfill event.
type cursorCoordinator struct {
	mu sync.Mutex

	dedupe      *stateTracker
	committed   *stateTracker
	pendingLive *stateTracker
	backfilling bool
}

func newCursorCoordinator(initial cursorState, backfilling bool) *cursorCoordinator {
	empty := newCursorState(initial.SourceConfigHash)
	return &cursorCoordinator{
		dedupe:      newStateTracker(initial),
		committed:   newStateTracker(initial),
		pendingLive: newStateTracker(empty),
		backfilling: backfilling,
	}
}

func (c *cursorCoordinator) accept(
	session *dedupeSession,
	timestamp time.Time,
	id string,
	path cursorPath,
) (cursorState, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	micros := timestamp.UnixMicro()
	session.seen[id]++
	if micros <= c.dedupe.highWater() && session.seen[id] <= c.dedupe.count(id) {
		return cursorState{}, true, false
	}
	c.dedupe.add(micros, id)

	if path == cursorPathLive && c.backfilling {
		c.pendingLive.add(micros, id)
		return cursorState{}, false, false
	}

	c.committed.add(micros, id)
	return c.committed.snapshot(), false, true
}

func (c *cursorCoordinator) finishBackfill() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.backfilling {
		return
	}
	c.committed.merge(c.pendingLive)
	c.pendingLive = newStateTracker(newCursorState(c.committed.state.SourceConfigHash))
	c.backfilling = false
}

func (c *cursorCoordinator) highWaterTime() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return cursorTime(c.dedupe.highWater())
}
