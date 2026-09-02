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
	"strconv"
	"strings"
	"time"
)

const cursorDateLayout = "2006-01-02 15:04:05-0700"

var acceptedDateLayouts = []string{
	"2006-01-02",
	"2006-01-02 15:04:05",
	cursorDateLayout,
}

func sourceConfigHash(cfg config) (string, error) {
	predicates := append([]string(nil), cfg.CommonConfig.Predicate...)
	processes := append([]string(nil), cfg.CommonConfig.Process...)
	slicesSort(predicates)
	slicesSort(processes)

	identity := struct {
		ArchiveFile string   `json:"archive_file,omitempty"`
		Start       string   `json:"start,omitempty"`
		End         string   `json:"end,omitempty"`
		Predicate   []string `json:"predicate,omitempty"`
		Process     []string `json:"process,omitempty"`
		Info        bool     `json:"info,omitempty"`
		Debug       bool     `json:"debug,omitempty"`
		Signpost    bool     `json:"signpost,omitempty"`
		Backfill    bool     `json:"backfill,omitempty"`
	}{
		ArchiveFile: cfg.ShowConfig.ArchiveFile,
		Start:       cfg.ShowConfig.Start,
		End:         cfg.ShowConfig.End,
		Predicate:   predicates,
		Process:     processes,
		Info:        cfg.CommonConfig.Info,
		Debug:       cfg.CommonConfig.Debug,
		Signpost:    cfg.CommonConfig.Signpost,
		Backfill:    cfg.Backfill,
	}

	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", fmt.Errorf("marshal unified logs source configuration: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// slicesSort is kept local so query.go remains buildable with the Go version
// used by older Beats maintenance branches when this input is backported.
func slicesSort(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func buildNativePredicate(cfg commonConfig) string {
	clauses := make([]string, 0, len(cfg.Predicate)+len(cfg.Process))
	for _, predicate := range cfg.Predicate {
		if predicate = strings.TrimSpace(predicate); predicate != "" {
			clauses = append(clauses, "("+predicate+")")
		}
	}
	for _, process := range cfg.Process {
		if process = strings.TrimSpace(process); process == "" {
			continue
		}
		if pid, err := strconv.ParseInt(process, 10, 32); err == nil {
			clauses = append(clauses, fmt.Sprintf("(processIdentifier == %d)", pid))
			continue
		}
		escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(process)
		clauses = append(clauses, `(process == "`+escaped+`")`)
	}
	return strings.Join(clauses, " OR ")
}

func parseConfiguredDate(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	for _, layout := range acceptedDateLayouts {
		if strings.Contains(layout, "-0700") {
			if parsed, err := time.Parse(layout, value); err == nil {
				return parsed, nil
			}
			continue
		}
		if parsed, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("not a valid date, accepted layouts are: %v", acceptedDateLayouts)
}

func configuredTimeBounds(cfg showConfig) (time.Time, time.Time, error) {
	start, err := parseConfiguredDate(cfg.Start)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("parse start date: %w", err)
	}
	end, err := parseConfiguredDate(cfg.End)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("parse end date: %w", err)
	}
	return start, end, nil
}

func resumeStart(state cursorState, configuredStart time.Time) time.Time {
	if state.HighWaterMicros == 0 {
		return configuredStart
	}
	resume := cursorTime(state.HighWaterMicros).Add(-cursorOverlap)
	if configuredStart.After(resume) {
		return configuredStart
	}
	return resume
}
