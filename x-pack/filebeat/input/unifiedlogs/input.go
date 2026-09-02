// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin

package unifiedlogs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	v2 "github.com/elastic/beats/v7/filebeat/input/v2"
	inputcursor "github.com/elastic/beats/v7/filebeat/input/v2/input-cursor"
	"github.com/elastic/beats/v7/libbeat/feature"
	"github.com/elastic/beats/v7/libbeat/statestore"
	conf "github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/monitoring"
	"github.com/elastic/go-concert/ctxtool"
)

const (
	inputName      = "unifiedlogs"
	srcArchiveName = "log-cmd-archive"
	srcPollName    = "log-cmd-poll"

	defaultStorePollInterval = time.Second
	defaultStoreSettleDelay  = 2 * time.Second
)

func Plugin(log *logp.Logger, store statestore.States) v2.Plugin {
	return v2.Plugin{
		Name:       inputName,
		Stability:  feature.Stable,
		Deprecated: false,
		Manager: &inputcursor.InputManager{
			Logger:     log,
			StateStore: store,
			Type:       inputName,
			Configure:  cursorConfigure,
		},
	}
}

type source struct {
	name string
}

func newSource(config config) source {
	if config.ShowConfig.ArchiveFile != "" {
		return source{name: srcArchiveName}
	}
	return source{name: srcPollName}
}

func (src source) Name() string { return src.name }

type input struct {
	config
	metrics *inputMetrics

	readerOnce sync.Once
	reader     nativeReader
	readerErr  error

	now          func() time.Time
	pollInterval time.Duration
	settleDelay  time.Duration
}

func cursorConfigure(cfg *conf.C, _ *logp.Logger) ([]inputcursor.Source, inputcursor.Input, error) {
	config := defaultConfig()
	if err := cfg.Unpack(&config); err != nil {
		return nil, nil, err
	}
	sources, inp := newCursorInput(config)
	return sources, inp, nil
}

func newCursorInput(config config) ([]inputcursor.Source, inputcursor.Input) {
	inp := &input{config: config}
	return []inputcursor.Source{newSource(config)}, inp
}

func (input *input) Name() string { return inputName }

func (input *input) Test(inputcursor.Source, v2.TestContext) error {
	_, err := input.getReader()
	return err
}

// Run starts the input and blocks until a one-shot read completes or the
// continuous collector is canceled.
func (input *input) Run(
	ctxt v2.Context,
	src inputcursor.Source,
	resumeCursor inputcursor.Cursor,
	pub inputcursor.Publisher,
) error {
	ctx := ctxtool.FromCanceller(ctxt.Cancelation)
	log := ctxt.Logger.With("source", src.Name())

	configHash, err := sourceConfigHash(input.config)
	if err != nil {
		return err
	}
	state, err := loadCursor(resumeCursor, configHash, log)
	if err != nil {
		return err
	}

	err = input.runWithStateAndMetrics(ctx, pub, ctxt.MetricsRegistry, log, state)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// runWithMetrics is retained as a narrow test seam. Production runs load a
// persisted cursor first and call runWithStateAndMetrics directly.
func (input *input) runWithMetrics(
	ctx context.Context,
	pub inputcursor.Publisher,
	reg *monitoring.Registry,
	log *logp.Logger,
) error {
	configHash, err := sourceConfigHash(input.config)
	if err != nil {
		return err
	}
	return input.runWithStateAndMetrics(ctx, pub, reg, log, newCursorState(configHash))
}

func (input *input) runWithStateAndMetrics(
	ctx context.Context,
	pub inputcursor.Publisher,
	reg *monitoring.Registry,
	log *logp.Logger,
	state cursorState,
) error {
	input.metrics = newInputMetrics(reg)
	reader, err := input.getReader()
	if err != nil {
		input.addError()
		return err
	}

	configuredStart, configuredEnd, err := configuredTimeBounds(input.ShowConfig)
	if err != nil {
		input.addError()
		return err
	}
	start := resumeStart(state, configuredStart)
	query := input.nativeQuery(start, configuredEnd)

	if input.isOneShot() {
		coordinator := newCursorCoordinator(state, false)
		log.Debugf("starting native OSLogStore one-shot read")
		err := input.readStore(ctx, reader, query, pub, coordinator, cursorPathHistory, log)
		if ctx.Err() != nil {
			return nil
		}
		if err == nil {
			log.Debugf("finished native OSLogStore one-shot read")
		}
		return err
	}

	boundary := input.currentTime()
	backfill := input.Backfill || !configuredStart.IsZero() || state.HighWaterMicros != 0
	coordinator := newCursorCoordinator(state, backfill)
	group, groupCtx := errgroup.WithContext(ctx)

	group.Go(func() error {
		streamQuery := input.nativeQuery(boundary, time.Time{})
		log.Debugf("starting native OSLogEventLiveStream at %s", boundary)
		err := input.stream(groupCtx, reader, streamQuery, pub, coordinator, log)
		if groupCtx.Err() != nil {
			return nil
		}
		var publishErr *eventPublishError
		if errors.As(err, &publishErr) {
			return err
		}

		input.addError()
		input.addStreamFallback()
		if err == nil {
			err = &nativeStreamFallbackError{Err: errors.New("stream ended unexpectedly")}
		}
		log.Warnf("native OSLogEventLiveStream unavailable; permanently switching to OSLogStore polling until restart: %v", err)
		return input.pollStore(groupCtx, reader, boundary, pub, coordinator, log)
	})

	if backfill {
		group.Go(func() error {
			historyQuery := input.nativeQuery(start, boundary)
			log.Debugf("starting concurrent native OSLogStore backfill through %s", boundary)
			err := input.readStore(groupCtx, reader, historyQuery, pub, coordinator, cursorPathHistory, log)
			if err != nil || groupCtx.Err() != nil {
				return err
			}
			coordinator.finishBackfill()
			log.Debugf("finished concurrent native OSLogStore backfill")
			return nil
		})
	}

	err = group.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (input *input) getReader() (nativeReader, error) {
	input.readerOnce.Do(func() {
		if input.reader != nil {
			return
		}
		input.reader, input.readerErr = newNativeReader()
	})
	return input.reader, input.readerErr
}

func (input *input) isOneShot() bool {
	return input.ShowConfig.ArchiveFile != "" || input.ShowConfig.End != ""
}

func (input *input) nativeQuery(start, end time.Time) nativeQuery {
	return nativeQuery{
		ArchiveFile: input.ShowConfig.ArchiveFile,
		Start:       start,
		End:         end,
		Predicate:   buildNativePredicate(input.CommonConfig),
		Info:        input.CommonConfig.Info,
		Debug:       input.CommonConfig.Debug,
		Signpost:    input.CommonConfig.Signpost,
	}
}

func (input *input) stream(
	ctx context.Context,
	reader nativeReader,
	query nativeQuery,
	pub inputcursor.Publisher,
	coordinator *cursorCoordinator,
	log *logp.Logger,
) error {
	session := newDedupeSession()
	return reader.Stream(ctx, query, func(event nativeEvent) error {
		return input.processNativeEvent(ctx, event, query, pub, coordinator, session, cursorPathLive, log)
	})
}

func (input *input) readStore(
	ctx context.Context,
	reader nativeReader,
	query nativeQuery,
	pub inputcursor.Publisher,
	coordinator *cursorCoordinator,
	path cursorPath,
	log *logp.Logger,
) error {
	if !query.Start.IsZero() && !query.End.IsZero() && query.Start.After(query.End) {
		return nil
	}

	session := newDedupeSession()
	err := reader.ReadStore(ctx, query, func(event nativeEvent) error {
		return input.processNativeEvent(ctx, event, query, pub, coordinator, session, path, log)
	})
	if err != nil && ctx.Err() == nil {
		input.addError()
		return fmt.Errorf("read native OSLogStore: %w", err)
	}
	return nil
}

func (input *input) processNativeEvent(
	ctx context.Context,
	event nativeEvent,
	query nativeQuery,
	pub inputcursor.Publisher,
	coordinator *cursorCoordinator,
	session *dedupeSession,
	path cursorPath,
	log *logp.Logger,
) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// OSLogStore positions are intentionally moved one millisecond earlier.
	// Enforce the requested interval here so both ends remain exactly inclusive.
	if !query.Start.IsZero() && event.Timestamp.Before(query.Start) {
		return nil
	}
	if !query.End.IsZero() && event.Timestamp.After(query.End) {
		return nil
	}
	if !includeNativeEvent(input.CommonConfig, event) {
		return nil
	}

	beatEvent, id, err := normalizeNativeEvent(event)
	if err != nil {
		input.addError()
		log.Errorf("normalize native unified log event: %v", err)
		return nil
	}
	cursor, duplicate, updateCursor := coordinator.accept(session, event.Timestamp, id, path)
	if duplicate {
		input.addDuplicate()
		return nil
	}

	var update any
	if updateCursor {
		update = cursor
	}
	if err := pub.Publish(beatEvent, update); err != nil {
		input.addError()
		return &eventPublishError{err: err}
	}
	return nil
}

func (input *input) pollStore(
	ctx context.Context,
	reader nativeReader,
	continuousStart time.Time,
	pub inputcursor.Publisher,
	coordinator *cursorCoordinator,
	log *logp.Logger,
) error {
	pollInterval := input.pollInterval
	if pollInterval <= 0 {
		pollInterval = defaultStorePollInterval
	}
	settleDelay := input.settleDelay
	if settleDelay <= 0 {
		settleDelay = defaultStoreSettleDelay
	}

	scanPosition := continuousStart
	if highWater := coordinator.highWaterTime(); highWater.After(scanPosition) {
		scanPosition = highWater
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		target := input.currentTime().Add(-settleDelay)
		if target.After(scanPosition) {
			start := scanPosition.Add(-cursorOverlap)
			if start.Before(continuousStart) {
				start = continuousStart
			}
			query := input.nativeQuery(start, target)
			log.Debugf("polling native OSLogStore from %s through %s", start, target)
			if err := input.readStore(ctx, reader, query, pub, coordinator, cursorPathLive, log); err != nil {
				return err
			}
			scanPosition = target
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (input *input) currentTime() time.Time {
	if input.now != nil {
		return input.now()
	}
	return time.Now()
}

type eventPublishError struct {
	err error
}

func (e *eventPublishError) Error() string {
	return fmt.Sprintf("publish native unified log event: %v", e.err)
}
func (e *eventPublishError) Unwrap() error { return e.err }
