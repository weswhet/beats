// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin

package unifiedlogs

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
)

type fakeCursorUnpacker struct {
	isNew bool
	value any
}

func (c fakeCursorUnpacker) IsNew() bool { return c.isNew }

func (c fakeCursorUnpacker) Unpack(to any) error {
	encoded, err := json.Marshal(c.value)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, to)
}

func testCursorID(n int) string {
	return fmt.Sprintf("%064x", n)
}

func testCursorTime(micros int64) time.Time {
	return time.Unix(0, micros*int64(time.Microsecond)).UTC()
}

func testCursorEvents(count int, timestampMicros int64) []cursorEvent {
	events := make([]cursorEvent, count)
	for i := range events {
		events[i] = cursorEvent{
			TimestampMicros: timestampMicros,
			ID:              testCursorID(i),
		}
	}
	return events
}

func TestNewCursorState(t *testing.T) {
	state := newCursorState("source-hash")

	assert.Equal(t, cursorVersion, state.Version, "new cursors should use the current cursor version")
	assert.Equal(t, int64(0), state.HighWaterMicros, "new cursors should start without a high-water mark")
	assert.Equal(t, "source-hash", state.SourceConfigHash, "new cursors should retain the source configuration hash")
	assert.Empty(t, state.RecentEventIDs, "new cursors should have no recent event identifiers")
}

func TestLoadCursorFrom(t *testing.T) {
	legacyTime := time.Date(2026, time.September, 1, 10, 0, 0, 123456000, time.UTC)
	matching := cursorState{
		Version:          cursorVersion,
		HighWaterMicros:  legacyTime.UnixMicro(),
		SourceConfigHash: "current-hash",
		RecentEventIDs: []cursorEvent{{
			TimestampMicros: legacyTime.UnixMicro(),
			ID:              testCursorID(1),
		}},
	}

	tests := []struct {
		name       string
		cursor     fakeCursorUnpacker
		want       cursorState
		wantErr    string
		wantRecent int
	}{
		{
			name:   "new cursor",
			cursor: fakeCursorUnpacker{isNew: true},
			want:   newCursorState("current-hash"),
		},
		{
			name:       "matching versioned cursor",
			cursor:     fakeCursorUnpacker{value: matching},
			want:       matching,
			wantRecent: 1,
		},
		{
			name: "configuration change resets cursor",
			cursor: fakeCursorUnpacker{value: cursorState{
				Version:          cursorVersion,
				HighWaterMicros:  legacyTime.UnixMicro(),
				SourceConfigHash: "old-hash",
			}},
			want: newCursorState("current-hash"),
		},
		{
			name:   "legacy timestamp migrates",
			cursor: fakeCursorUnpacker{value: legacyTime},
			want: cursorState{
				Version:          cursorVersion,
				HighWaterMicros:  legacyTime.UnixMicro(),
				SourceConfigHash: "current-hash",
			},
		},
		{
			name:    "incompatible cursor fails",
			cursor:  fakeCursorUnpacker{value: "not a cursor"},
			wantErr: "unpack cursor as versioned state or legacy timestamp",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := loadCursorFrom(test.cursor, "current-hash", logp.NewLogger("unifiedlogs_cursor_test"))
			if test.wantErr != "" {
				require.Error(t, err, "an incompatible saved cursor should fail loading")
				assert.Contains(t, err.Error(), test.wantErr, "the cursor error should describe both supported formats")
				return
			}
			require.NoError(t, err, "a supported cursor format should load")
			assert.Equal(t, test.want, got, "the loaded cursor should match the expected migrated or reset state")
			assert.Len(t, got.RecentEventIDs, test.wantRecent, "the loaded cursor should retain the expected recent-ID multiplicity")
		})
	}
}

func TestValidateCursorState(t *testing.T) {
	tests := []struct {
		name      string
		state     cursorState
		wantError string
	}{
		{
			name: "valid state",
			state: cursorState{
				Version:          cursorVersion,
				HighWaterMicros:  123,
				SourceConfigHash: "source-hash",
				RecentEventIDs: []cursorEvent{{
					TimestampMicros: 123,
					ID:              testCursorID(1),
				}},
			},
		},
		{
			name: "unsupported version",
			state: cursorState{
				Version:          cursorVersion + 1,
				SourceConfigHash: "source-hash",
			},
			wantError: "unsupported version",
		},
		{
			name: "empty source configuration hash",
			state: cursorState{
				Version: cursorVersion,
			},
			wantError: "source_config_hash is empty",
		},
		{
			name: "short event identifier",
			state: cursorState{
				Version:          cursorVersion,
				SourceConfigHash: "source-hash",
				RecentEventIDs:   []cursorEvent{{ID: strings.Repeat("a", 63)}},
			},
			wantError: "recent_event_ids[0] is not a SHA-256 identifier",
		},
		{
			name: "non-hex event identifier",
			state: cursorState{
				Version:          cursorVersion,
				SourceConfigHash: "source-hash",
				RecentEventIDs:   []cursorEvent{{ID: strings.Repeat("z", 64)}},
			},
			wantError: "recent_event_ids[0] is not a SHA-256 identifier",
		},
		{
			name: "exactly capped event identifier list",
			state: cursorState{
				Version:          cursorVersion,
				SourceConfigHash: "source-hash",
				RecentEventIDs:   testCursorEvents(cursorRecentIDCap, 123),
			},
		},
		{
			name: "event identifier list over cap",
			state: cursorState{
				Version:          cursorVersion,
				SourceConfigHash: "source-hash",
				RecentEventIDs:   testCursorEvents(cursorRecentIDCap+1, 123),
			},
			wantError: "maximum is 100000",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateCursorState(test.state)
			if test.wantError == "" {
				require.NoError(t, err, "valid cursor state should pass validation")
				return
			}

			require.Error(t, err, "invalid cursor state should fail validation")
			assert.Contains(t, err.Error(), test.wantError, "cursor validation errors should identify the invalid state field")
		})
	}
}

func TestCompactCursorState(t *testing.T) {
	const highWaterMicros = int64(10_000_000)

	original := cursorState{
		Version:          cursorVersion + 10,
		HighWaterMicros:  highWaterMicros,
		SourceConfigHash: "source-hash",
		RecentEventIDs: []cursorEvent{
			{TimestampMicros: highWaterMicros - cursorOverlapMicro - 1, ID: testCursorID(1)},
			{TimestampMicros: highWaterMicros + 2, ID: testCursorID(2)},
			{TimestampMicros: highWaterMicros - cursorOverlapMicro, ID: testCursorID(3)},
			{TimestampMicros: highWaterMicros - 1, ID: testCursorID(4)},
		},
	}
	before := original
	before.RecentEventIDs = append([]cursorEvent(nil), original.RecentEventIDs...)

	compacted := compactCursorState(original)

	require.Equal(t, cursorVersion, compacted.Version, "compaction should normalize the cursor version")
	assert.Equal(t, highWaterMicros, compacted.HighWaterMicros, "compaction should preserve the high-water mark")
	assert.Equal(t, "source-hash", compacted.SourceConfigHash, "compaction should preserve the source configuration hash")
	assert.Equal(t, []cursorEvent{
		{TimestampMicros: highWaterMicros - cursorOverlapMicro, ID: testCursorID(3)},
		{TimestampMicros: highWaterMicros - 1, ID: testCursorID(4)},
		{TimestampMicros: highWaterMicros + 2, ID: testCursorID(2)},
	}, compacted.RecentEventIDs, "compaction should sort entries and retain the inclusive five-second overlap")
	assert.Equal(t, before, original, "compaction should not mutate its input state")

	compacted.RecentEventIDs[0].ID = testCursorID(99)
	assert.Equal(t, testCursorID(3), original.RecentEventIDs[2].ID, "compaction should return independent recent-event storage")
}

func TestCompactCursorStateCapsRecentIDs(t *testing.T) {
	const highWaterMicros = int64(20_000_000)

	state := cursorState{
		Version:          cursorVersion,
		HighWaterMicros:  highWaterMicros,
		SourceConfigHash: "source-hash",
		RecentEventIDs:   make([]cursorEvent, cursorRecentIDCap+1),
	}
	for i := range state.RecentEventIDs {
		state.RecentEventIDs[i] = cursorEvent{
			TimestampMicros: highWaterMicros - int64(cursorRecentIDCap-i),
			ID:              testCursorID(i),
		}
	}

	compacted := compactCursorState(state)

	require.Len(t, compacted.RecentEventIDs, cursorRecentIDCap, "compaction should retain exactly the configured recent-event cap")
	assert.Equal(t, highWaterMicros-int64(cursorRecentIDCap-1), compacted.RecentEventIDs[0].TimestampMicros, "compaction should remove the oldest entry when the cap is exceeded")
	assert.Equal(t, testCursorID(1), compacted.RecentEventIDs[0].ID, "compaction should remove only the oldest entry at cap plus one")
	assert.Equal(t, highWaterMicros, compacted.RecentEventIDs[len(compacted.RecentEventIDs)-1].TimestampMicros, "compaction should retain the newest entry")
}

func TestStateTrackerRetainsMultisetCounts(t *testing.T) {
	const highWaterMicros = int64(30_000_000)
	duplicateID := testCursorID(1)
	outsideID := testCursorID(2)

	tracker := newStateTracker(cursorState{
		Version:          cursorVersion,
		HighWaterMicros:  highWaterMicros,
		SourceConfigHash: "source-hash",
		RecentEventIDs: []cursorEvent{
			{TimestampMicros: highWaterMicros - cursorOverlapMicro, ID: duplicateID},
			{TimestampMicros: highWaterMicros - cursorOverlapMicro - 1, ID: outsideID},
			{TimestampMicros: highWaterMicros, ID: duplicateID},
		},
	})

	assert.Equal(t, 2, tracker.count(duplicateID), "state trackers should retain repeated identifiers as a multiset")
	assert.Equal(t, 0, tracker.count(outsideID), "state trackers should discard identifiers outside the five-second overlap")
	require.Len(t, tracker.state.RecentEventIDs, 2, "state trackers should compact entries outside the overlap on construction")

	tracker.add(highWaterMicros+cursorOverlapMicro+1, testCursorID(3))
	assert.Equal(t, 0, tracker.count(duplicateID), "advancing the high-water mark should evict entries that fall outside the new overlap")
	assert.Equal(t, highWaterMicros+cursorOverlapMicro+1, tracker.highWater(), "adding a newer event should advance the high-water mark")
}

func TestCursorCoordinatorDeduplicatesAcrossReadSessions(t *testing.T) {
	const highWaterMicros = int64(40_000_000)
	duplicateID := testCursorID(1)

	coordinator := newCursorCoordinator(cursorState{
		Version:          cursorVersion,
		HighWaterMicros:  highWaterMicros,
		SourceConfigHash: "source-hash",
		RecentEventIDs: []cursorEvent{{
			TimestampMicros: highWaterMicros,
			ID:              duplicateID,
		}},
	}, false)

	firstSession := newDedupeSession()
	state, duplicate, carriesCursor := coordinator.accept(firstSession, testCursorTime(highWaterMicros), duplicateID, cursorPathHistory)
	assert.True(t, duplicate, "the first occurrence from an overlap session should be dropped when it exists in the saved multiset")
	assert.False(t, carriesCursor, "a dropped overlap event should not carry a cursor")
	assert.Equal(t, cursorState{}, state, "a dropped overlap event should not return cursor state")

	state, duplicate, carriesCursor = coordinator.accept(firstSession, testCursorTime(highWaterMicros), duplicateID, cursorPathHistory)
	assert.False(t, duplicate, "a second identical record in the same session should be treated as a distinct multiset occurrence")
	assert.True(t, carriesCursor, "a distinct repeated record should carry a cursor")
	require.Equal(t, int64(highWaterMicros), state.HighWaterMicros, "accepted repeated records should preserve the high-water mark")
	assert.Equal(t, 2, countCursorID(state, duplicateID), "accepted repeated records should remain distinguishable in the returned multiset")

	secondSession := newDedupeSession()
	state, duplicate, carriesCursor = coordinator.accept(secondSession, testCursorTime(highWaterMicros), duplicateID, cursorPathHistory)
	assert.True(t, duplicate, "each new read session should independently drop records already represented by the saved multiset")
	assert.False(t, carriesCursor, "a duplicate from a later read session should not carry a cursor")
	assert.Equal(t, cursorState{}, state, "a duplicate from a later read session should not return cursor state")

	newID := testCursorID(2)
	state, duplicate, carriesCursor = coordinator.accept(secondSession, testCursorTime(highWaterMicros-1), newID, cursorPathHistory)
	assert.False(t, duplicate, "an identifier absent from the saved multiset should be accepted")
	assert.True(t, carriesCursor, "an accepted history event should carry a cursor")
	assert.Equal(t, 1, countCursorID(state, newID), "the returned cursor should include the newly accepted identifier once")
}

func TestCursorCoordinatorGatesLiveCursorsDuringBackfill(t *testing.T) {
	const highWaterMicros = int64(50_000_000)
	liveID := testCursorID(1)
	historyID := testCursorID(2)

	coordinator := newCursorCoordinator(newCursorState("source-hash"), true)
	liveSession := newDedupeSession()

	state, duplicate, carriesCursor := coordinator.accept(liveSession, testCursorTime(highWaterMicros+4), liveID, cursorPathLive)
	assert.False(t, duplicate, "the first live event should be accepted during backfill")
	assert.False(t, carriesCursor, "live events should not carry a cursor while history is backfilling")
	assert.Equal(t, cursorState{}, state, "live events should return no cursor state while history is backfilling")
	assert.Equal(t, highWaterMicros+4, coordinator.highWaterTime().UnixMicro(), "the dedupe high-water mark should include pending live events")

	historySession := newDedupeSession()
	state, duplicate, carriesCursor = coordinator.accept(historySession, testCursorTime(highWaterMicros+1), historyID, cursorPathHistory)
	assert.False(t, duplicate, "a new history event should be accepted during backfill")
	assert.True(t, carriesCursor, "history events should carry cursors during backfill")
	assert.Equal(t, highWaterMicros+1, state.HighWaterMicros, "history cursors should not advance past pending live events")
	assert.Equal(t, 1, countCursorID(state, historyID), "history cursors should include the accepted history event")
	assert.Equal(t, 0, countCursorID(state, liveID), "history cursors should exclude pending live events")

	duplicateState, duplicate, carriesCursor := coordinator.accept(newDedupeSession(), testCursorTime(highWaterMicros+4), liveID, cursorPathLive)
	assert.True(t, duplicate, "a live event replayed by another stream session should be deduplicated")
	assert.False(t, carriesCursor, "a deduplicated live event should not carry a cursor")
	assert.Equal(t, cursorState{}, duplicateState, "a deduplicated live event should return no cursor state")

	coordinator.finishBackfill()
	assert.False(t, coordinator.backfilling, "finishing backfill should disable live cursor gating")
	assert.Equal(t, highWaterMicros+4, coordinator.committed.highWater(), "finishing backfill should merge the pending live high-water mark")
	assert.Equal(t, 1, coordinator.committed.count(historyID), "finishing backfill should merge accepted history identifiers")
	assert.Equal(t, 1, coordinator.committed.count(liveID), "finishing backfill should merge accepted live identifiers")
	assert.Empty(t, coordinator.pendingLive.state.RecentEventIDs, "finishing backfill should clear pending live cursor state")

	committedBeforeSecondFinish := coordinator.committed.snapshot()
	coordinator.finishBackfill()
	assert.Equal(t, committedBeforeSecondFinish, coordinator.committed.snapshot(), "finishing backfill more than once should be idempotent")

	postBackfillID := testCursorID(3)
	state, duplicate, carriesCursor = coordinator.accept(newDedupeSession(), testCursorTime(highWaterMicros+5), postBackfillID, cursorPathLive)
	assert.False(t, duplicate, "new live events should be accepted after backfill completes")
	assert.True(t, carriesCursor, "live events should carry cursors after backfill completes")
	assert.Equal(t, highWaterMicros+5, state.HighWaterMicros, "post-backfill live events should advance the committed cursor")
}

func TestCursorCoordinatorDoesNotGateLiveCursorsWithoutBackfill(t *testing.T) {
	const timestampMicros = int64(60_000_000)
	coordinator := newCursorCoordinator(newCursorState("source-hash"), false)

	state, duplicate, carriesCursor := coordinator.accept(newDedupeSession(), testCursorTime(timestampMicros), testCursorID(1), cursorPathLive)
	assert.False(t, duplicate, "a new live event should be accepted when backfill is disabled")
	assert.True(t, carriesCursor, "live events should carry cursors when backfill is disabled")
	assert.Equal(t, timestampMicros, state.HighWaterMicros, "a live cursor should record the accepted event timestamp")
}

func TestCursorCoordinatorReturnsImmutableCursorSnapshots(t *testing.T) {
	const highWaterMicros = int64(70_000_000)
	coordinator := newCursorCoordinator(newCursorState("source-hash"), false)

	first, duplicate, carriesCursor := coordinator.accept(newDedupeSession(), testCursorTime(highWaterMicros+1), testCursorID(1), cursorPathHistory)
	require.False(t, duplicate, "the first history event should not be deduplicated")
	require.True(t, carriesCursor, "the first history event should carry a cursor")
	firstCopy := first
	firstCopy.RecentEventIDs = append([]cursorEvent(nil), first.RecentEventIDs...)

	second, duplicate, carriesCursor := coordinator.accept(newDedupeSession(), testCursorTime(highWaterMicros+2), testCursorID(2), cursorPathHistory)
	require.False(t, duplicate, "the second history event should not be deduplicated")
	require.True(t, carriesCursor, "the second history event should carry a cursor")

	assert.Equal(t, highWaterMicros+1, first.HighWaterMicros, "an earlier cursor snapshot should not advance with later events")
	assert.Equal(t, firstCopy.RecentEventIDs, first.RecentEventIDs, "later accepts should not mutate an earlier cursor snapshot")
	assert.Equal(t, highWaterMicros+2, second.HighWaterMicros, "a later cursor snapshot should include the later event")
	assert.Len(t, second.RecentEventIDs, len(first.RecentEventIDs)+1, "a later cursor snapshot should include one additional event identifier")

	first.RecentEventIDs[0].ID = testCursorID(99)
	assert.NotEqual(t, first.RecentEventIDs[0].ID, coordinator.committed.state.RecentEventIDs[0].ID, "mutating a returned cursor snapshot should not mutate coordinator state")
}

func TestCursorSourceConfigHash(t *testing.T) {
	base := config{
		ShowConfig: showConfig{
			ArchiveFile: "/tmp/logs.logarchive",
			Start:       "2024-12-04",
			End:         "2024-12-05",
		},
		CommonConfig: commonConfig{
			Predicate: []string{`process == "alpha"`, "pid == 1"},
			Process:   []string{"beta", "42"},
			Info:      true,
			Debug:     true,
			Signpost:  true,
		},
		Backfill: true,
	}

	hash, err := sourceConfigHash(base)
	require.NoError(t, err, "a valid unified logs source configuration should hash successfully")
	require.Len(t, hash, 64, "source configuration hashes should be SHA-256 hex strings")

	reordered := base
	reordered.CommonConfig.Predicate = []string{"pid == 1", `process == "alpha"`}
	reordered.CommonConfig.Process = []string{"42", "beta"}
	reorderedHash, err := sourceConfigHash(reordered)
	require.NoError(t, err, "reordered source selectors should hash successfully")
	assert.Equal(t, hash, reorderedHash, "selector ordering should not reset an equivalent source cursor")

	changed := base
	changed.CommonConfig.Info = false
	changedHash, err := sourceConfigHash(changed)
	require.NoError(t, err, "a changed source configuration should hash successfully")
	assert.NotEqual(t, hash, changedHash, "changing a source-affecting option should produce a new cursor hash")

	changed = base
	changed.CommonConfig.Predicate = []string{`process == "different"`}
	changedHash, err = sourceConfigHash(changed)
	require.NoError(t, err, "a changed predicate configuration should hash successfully")
	assert.NotEqual(t, hash, changedHash, "changing predicates should produce a new cursor hash")
}

func TestResumeStart(t *testing.T) {
	const highWaterMicros = int64(80_000_000)
	configuredStart := testCursorTime(highWaterMicros - 2*cursorOverlapMicro)

	tests := []struct {
		name       string
		state      cursorState
		configured time.Time
		wantMicros int64
	}{
		{
			name:       "new cursor uses configured start",
			state:      newCursorState("source-hash"),
			configured: configuredStart,
			wantMicros: configuredStart.UnixMicro(),
		},
		{
			name: "saved cursor starts five seconds before high-water mark",
			state: cursorState{
				Version:          cursorVersion,
				HighWaterMicros:  highWaterMicros,
				SourceConfigHash: "source-hash",
			},
			configured: time.Time{},
			wantMicros: highWaterMicros - cursorOverlapMicro,
		},
		{
			name: "configured start wins when it is later",
			state: cursorState{
				Version:          cursorVersion,
				HighWaterMicros:  highWaterMicros,
				SourceConfigHash: "source-hash",
			},
			configured: testCursorTime(highWaterMicros + 1),
			wantMicros: highWaterMicros + 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := resumeStart(test.state, test.configured)
			assert.Equal(t, test.wantMicros, got.UnixMicro(), "resume start should honor the saved cursor overlap and configured lower bound")
		})
	}
}

func countCursorID(state cursorState, id string) int {
	count := 0
	for _, event := range state.RecentEventIDs {
		if event.ID == id {
			count++
		}
	}
	return count
}
