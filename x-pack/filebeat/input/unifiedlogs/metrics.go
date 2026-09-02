// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin

package unifiedlogs

import (
	"github.com/elastic/elastic-agent-libs/monitoring"
)

type inputMetrics struct {
	errs            *monitoring.Uint
	streamFallbacks *monitoring.Uint
	duplicates      *monitoring.Uint
}

func newInputMetrics(reg *monitoring.Registry) *inputMetrics {
	if reg == nil {
		return nil
	}

	out := &inputMetrics{
		errs:            monitoring.NewUint(reg, "errors_total"),
		streamFallbacks: monitoring.NewUint(reg, "stream_fallbacks_total"),
		duplicates:      monitoring.NewUint(reg, "duplicates_dropped_total"),
	}

	return out
}

func (input *input) addError() {
	if input.metrics != nil {
		input.metrics.errs.Add(1)
	}
}

func (input *input) addStreamFallback() {
	if input.metrics != nil {
		input.metrics.streamFallbacks.Add(1)
	}
}

func (input *input) addDuplicate() {
	if input.metrics != nil {
		input.metrics.duplicates.Add(1)
	}
}
