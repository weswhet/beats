// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin

package unifiedlogs

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	inputcursor "github.com/elastic/beats/v7/filebeat/input/v2/input-cursor"
	"github.com/elastic/beats/v7/libbeat/beat"
	"github.com/elastic/beats/v7/libbeat/monitoring/inputmon"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/monitoring"
)

var _ inputcursor.Publisher = (*recordingPublisher)(nil)

type recordingPublisher struct {
	mu sync.Mutex

	events  []beat.Event
	cursors []any
	err     error
	notify  chan struct{}
	onEvent func(beat.Event, any)
}

func (p *recordingPublisher) Publish(event beat.Event, cursor any) error {
	p.mu.Lock()
	p.events = append(p.events, event)
	p.cursors = append(p.cursors, cursor)
	err := p.err
	onEvent := p.onEvent
	notify := p.notify
	p.mu.Unlock()

	if onEvent != nil {
		onEvent(event, cursor)
	}
	if notify != nil {
		select {
		case notify <- struct{}{}:
		default:
		}
	}
	return err
}

func (p *recordingPublisher) snapshot() ([]beat.Event, []any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]beat.Event(nil), p.events...), append([]any(nil), p.cursors...)
}

type fakeNativeReader struct {
	mu sync.Mutex

	storeQueries  []nativeQuery
	streamQueries []nativeQuery
	storeFn       func(context.Context, nativeQuery, func(nativeEvent) error) error
	streamFn      func(context.Context, nativeQuery, func(nativeEvent) error) error
}

func (r *fakeNativeReader) ReadStore(ctx context.Context, query nativeQuery, emit func(nativeEvent) error) error {
	r.mu.Lock()
	r.storeQueries = append(r.storeQueries, query)
	fn := r.storeFn
	r.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn(ctx, query, emit)
}

func (r *fakeNativeReader) Stream(ctx context.Context, query nativeQuery, emit func(nativeEvent) error) error {
	r.mu.Lock()
	r.streamQueries = append(r.streamQueries, query)
	fn := r.streamFn
	r.mu.Unlock()
	if fn == nil {
		<-ctx.Done()
		return ctx.Err()
	}
	return fn(ctx, query, emit)
}

func (r *fakeNativeReader) queries() ([]nativeQuery, []nativeQuery) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]nativeQuery(nil), r.storeQueries...), append([]nativeQuery(nil), r.streamQueries...)
}

func testNativeLog(timestamp time.Time, message string) nativeEvent {
	return nativeEvent{
		Timestamp: timestamp,
		Kind:      nativeKindLog,
		Level:     nativeLevelDefault,
		Message:   message,
		Process:   "test-process",
	}
}

func TestSourceNamesRemainStable(t *testing.T) {
	tests := []struct {
		name string
		cfg  config
		want string
	}{
		{name: "local store", cfg: config{}, want: srcPollName},
		{name: "archive store", cfg: config{ShowConfig: showConfig{ArchiveFile: "test.logarchive"}}, want: srcArchiveName},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, newSource(test.cfg).Name(), "the hidden source name must remain registry-compatible")
		})
	}
}

func TestDefaultInputStreamsNativeEvents(t *testing.T) {
	boundary := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	reader := &fakeNativeReader{
		streamFn: func(ctx context.Context, query nativeQuery, emit func(nativeEvent) error) error {
			if err := emit(testNativeLog(boundary.Add(time.Second), "live")); err != nil {
				return err
			}
			<-ctx.Done()
			return ctx.Err()
		},
	}
	pub := &recordingPublisher{onEvent: func(beat.Event, any) { cancel() }}
	inp := &input{config: config{}, reader: reader, now: func() time.Time { return boundary }}

	err := inp.runWithMetrics(ctx, pub, nil, logp.NewLogger("unifiedlogs_test"))
	require.NoError(t, err, "canceling a native live stream should stop the input cleanly")

	storeQueries, streamQueries := reader.queries()
	assert.Empty(t, storeQueries, "a new default input should not read historical Store data")
	require.Len(t, streamQueries, 1, "a new default input should create one native stream")
	assert.Equal(t, boundary, streamQueries[0].Start, "the native stream should begin at the run boundary")

	events, cursors := pub.snapshot()
	require.Len(t, events, 1, "the live native event should be published once")
	require.Len(t, cursors, 1, "each published event should have a corresponding cursor slot")
	assert.Equal(t, boundary.Add(time.Second), events[0].Timestamp, "the outer timestamp should be the native event date")
	assert.IsType(t, cursorState{}, cursors[0], "live events should advance a versioned cursor when no backfill is active")
}

func TestOneShotStoreModes(t *testing.T) {
	end := "2026-09-01 10:00:00+0000"
	tests := []struct {
		name        string
		cfg         config
		wantArchive string
		wantEnd     time.Time
	}{
		{
			name:        "archive",
			cfg:         config{ShowConfig: showConfig{ArchiveFile: "/tmp/test.logarchive"}},
			wantArchive: "/tmp/test.logarchive",
		},
		{
			name:    "bounded local history",
			cfg:     config{ShowConfig: showConfig{End: end}},
			wantEnd: time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &fakeNativeReader{}
			inp := &input{config: test.cfg, reader: reader}
			err := inp.runWithMetrics(context.Background(), &recordingPublisher{}, nil, logp.NewLogger("unifiedlogs_test"))
			require.NoError(t, err, "a successful one-shot native Store read should complete")

			storeQueries, streamQueries := reader.queries()
			require.Len(t, storeQueries, 1, "a one-shot input should take one fixed Store snapshot")
			assert.Empty(t, streamQueries, "a one-shot input should never start the private stream")
			assert.Equal(t, test.wantArchive, storeQueries[0].ArchiveFile, "the Store query should preserve the archive path")
			assert.True(t, test.wantEnd.Equal(storeQueries[0].End), "the Store query should preserve the inclusive end date")
		})
	}
}

func TestStoreBoundsAreExactlyInclusive(t *testing.T) {
	start := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Second)
	reader := &fakeNativeReader{
		storeFn: func(_ context.Context, _ nativeQuery, emit func(nativeEvent) error) error {
			for _, event := range []nativeEvent{
				testNativeLog(start.Add(-time.Microsecond), "before"),
				testNativeLog(start, "start"),
				testNativeLog(end, "end"),
				testNativeLog(end.Add(time.Microsecond), "after"),
			} {
				if err := emit(event); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cfg := config{ShowConfig: showConfig{
		ArchiveFile: "/tmp/test.logarchive",
		Start:       start.Format(cursorDateLayout),
		End:         end.Format(cursorDateLayout),
	}}
	pub := &recordingPublisher{}
	inp := &input{config: cfg, reader: reader}

	err := inp.runWithMetrics(context.Background(), pub, nil, logp.NewLogger("unifiedlogs_test"))
	require.NoError(t, err, "an inclusive bounded Store read should complete")
	events, _ := pub.snapshot()
	require.Len(t, events, 2, "only events on or inside the exact requested bounds should be published")
	assert.Equal(t, start, events[0].Timestamp, "an event exactly at the start should be included")
	assert.Equal(t, end, events[1].Timestamp, "an event exactly at the end should be included")
}

func TestBackfillAndStreamRunConcurrently(t *testing.T) {
	boundary := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	streamPublished := make(chan struct{})
	storeFinished := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())

	reader := &fakeNativeReader{}
	reader.streamFn = func(ctx context.Context, _ nativeQuery, emit func(nativeEvent) error) error {
		if err := emit(testNativeLog(boundary.Add(time.Second), "live-during-backfill")); err != nil {
			return err
		}
		close(streamPublished)
		<-ctx.Done()
		return ctx.Err()
	}
	reader.storeFn = func(_ context.Context, _ nativeQuery, emit func(nativeEvent) error) error {
		select {
		case <-streamPublished:
		case <-time.After(5 * time.Second):
			return errors.New("native stream did not start concurrently")
		}
		if err := emit(testNativeLog(boundary.Add(-time.Second), "history")); err != nil {
			return err
		}
		close(storeFinished)
		return nil
	}

	pub := &recordingPublisher{notify: make(chan struct{}, 4)}
	inp := &input{
		config: config{Backfill: true},
		reader: reader,
		now:    func() time.Time { return boundary },
	}
	done := make(chan error, 1)
	go func() {
		done <- inp.runWithMetrics(ctx, pub, nil, logp.NewLogger("unifiedlogs_test"))
	}()

	select {
	case <-storeFinished:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for concurrent native backfill")
	}
	require.Eventually(t, func() bool {
		events, _ := pub.snapshot()
		return len(events) == 2
	}, 5*time.Second, time.Millisecond, "both live and historical native events should be published")
	cancel()
	require.NoError(t, <-done, "canceling after concurrent backfill should stop the input cleanly")

	events, cursors := pub.snapshot()
	require.Len(t, events, 2, "concurrent backfill should publish one live and one historical event")
	require.Len(t, cursors, 2, "concurrent events should have matching cursor slots")
	assert.Nil(t, cursors[0], "a live event published before backfill completes must not advance the cursor")
	assert.IsType(t, cursorState{}, cursors[1], "a historical event should advance the cursor while backfill is active")

	storeQueries, streamQueries := reader.queries()
	require.Len(t, storeQueries, 1, "backfill should use one fixed Store snapshot")
	require.Len(t, streamQueries, 1, "backfill should run beside one live stream")
	assert.Equal(t, boundary, storeQueries[0].End, "the backfill should end at the live collection boundary")
	assert.Equal(t, boundary, streamQueries[0].Start, "the live stream should start at the same boundary")
}

func TestResumeUsesFiveSecondStoreOverlap(t *testing.T) {
	boundary := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	highWater := boundary.Add(-time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	reader := &fakeNativeReader{
		storeFn: func(context.Context, nativeQuery, func(nativeEvent) error) error {
			cancel()
			return nil
		},
	}
	inp := &input{config: config{}, reader: reader, now: func() time.Time { return boundary }}
	state := newCursorState("source-hash")
	state.HighWaterMicros = highWater.UnixMicro()

	err := inp.runWithStateAndMetrics(ctx, &recordingPublisher{}, nil, logp.NewLogger("unifiedlogs_test"), state)
	require.NoError(t, err, "canceling after the resume Store query should stop cleanly")
	storeQueries, streamQueries := reader.queries()
	require.Len(t, storeQueries, 1, "a resumed input should backfill the Store gap")
	require.Len(t, streamQueries, 1, "a resumed input should also start live collection")
	assert.True(t, highWater.Add(-cursorOverlap).Equal(storeQueries[0].Start), "resume should query the full five-second overlap")
	assert.Equal(t, boundary, storeQueries[0].End, "resume history should be bounded by the stream start")
}

func TestStreamFailurePermanentlyFallsBackToStorePolling(t *testing.T) {
	boundary := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	var nowCalls atomic.Int32
	var storeCalls atomic.Int32
	reader := &fakeNativeReader{
		streamFn: func(context.Context, nativeQuery, func(nativeEvent) error) error {
			return &nativeStreamFallbackError{Reason: 6, Err: errNativeReaderUnsupported}
		},
		storeFn: func(_ context.Context, query nativeQuery, emit func(nativeEvent) error) error {
			storeCalls.Add(1)
			if err := emit(testNativeLog(query.End, "polled")); err != nil {
				return err
			}
			cancel()
			return nil
		},
	}
	inp := &input{
		config:       config{},
		reader:       reader,
		pollInterval: time.Millisecond,
		settleDelay:  time.Second,
		now: func() time.Time {
			if nowCalls.Add(1) == 1 {
				return boundary
			}
			return boundary.Add(10 * time.Second)
		},
	}
	pub := &recordingPublisher{}

	err := inp.runWithMetrics(ctx, pub, testMetricsRegistry(), logp.NewLogger("unifiedlogs_test"))
	require.NoError(t, err, "Store polling fallback should stop cleanly when canceled")
	assert.Equal(t, int32(1), storeCalls.Load(), "the fallback should poll one snapshot before cancellation")

	storeQueries, streamQueries := reader.queries()
	require.Len(t, streamQueries, 1, "private streaming should be attempted only once per input run")
	require.Len(t, storeQueries, 1, "the failed private stream should fall back to Store polling")
	assert.Equal(t, boundary, storeQueries[0].Start, "the first fallback poll should not read before the run boundary")
	assert.Equal(t, boundary.Add(9*time.Second), storeQueries[0].End, "polling should honor the configured settling delay")
	events, _ := pub.snapshot()
	assert.Len(t, events, 1, "the Store polling fallback should publish its native event")
}

func TestFatalStoreErrorStopsInput(t *testing.T) {
	sentinel := errors.New("store failed")
	reader := &fakeNativeReader{
		storeFn: func(context.Context, nativeQuery, func(nativeEvent) error) error {
			return sentinel
		},
	}
	inp := &input{
		config: config{ShowConfig: showConfig{ArchiveFile: "/tmp/test.logarchive"}},
		reader: reader,
	}

	err := inp.runWithMetrics(context.Background(), &recordingPublisher{}, nil, logp.NewLogger("unifiedlogs_test"))
	require.Error(t, err, "a fatal native Store error should stop the input")
	assert.ErrorIs(t, err, sentinel, "the fatal Store error should retain its cause")
}

func TestCancellationStopsBlockedNativeStore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	reader := &fakeNativeReader{
		storeFn: func(ctx context.Context, _ nativeQuery, _ func(nativeEvent) error) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		},
	}
	inp := &input{
		config: config{ShowConfig: showConfig{ArchiveFile: "/tmp/test.logarchive"}},
		reader: reader,
	}
	done := make(chan error, 1)
	go func() {
		done <- inp.runWithMetrics(ctx, &recordingPublisher{}, nil, logp.NewLogger("unifiedlogs_test"))
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the native Store read to start")
	}
	cancel()
	require.NoError(t, <-done, "context cancellation should stop a blocked Store read without a fatal error")
}

func testMetricsRegistry() *monitoring.Registry {
	return inputmon.NewMetricsRegistry(
		"", "", monitoring.NewRegistry(), logp.NewLogger("test"))
}
