// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin

package unifiedlogs

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildNativePredicate(t *testing.T) {
	tests := []struct {
		name string
		cfg  commonConfig
		want string
	}{
		{
			name: "empty selectors",
			want: "",
		},
		{
			name: "one predicate",
			cfg:  commonConfig{Predicate: []string{"pid == 1"}},
			want: "(pid == 1)",
		},
		{
			name: "multiple predicates are ORed",
			cfg: commonConfig{Predicate: []string{
				`process == "loginwindow"`,
				`sender == "Security"`,
			}},
			want: `(process == "loginwindow") OR (sender == "Security")`,
		},
		{
			name: "blank predicates are ignored",
			cfg: commonConfig{Predicate: []string{
				" ",
				"pid == 1",
				"\t",
			}},
			want: "(pid == 1)",
		},
		{
			name: "process name",
			cfg:  commonConfig{Process: []string{"sudo"}},
			want: `(process == "sudo")`,
		},
		{
			name: "positive process PID",
			cfg:  commonConfig{Process: []string{"42"}},
			want: `(processIdentifier == 42)`,
		},
		{
			name: "negative process PID",
			cfg:  commonConfig{Process: []string{"-7"}},
			want: `(processIdentifier == -7)`,
		},
		{
			name: "process whitespace is trimmed",
			cfg:  commonConfig{Process: []string{"  sudo  "}},
			want: `(process == "sudo")`,
		},
		{
			name: "blank processes are ignored",
			cfg: commonConfig{Process: []string{
				"",
				"\n",
				"42",
			}},
			want: `(processIdentifier == 42)`,
		},
		{
			name: "quote in process name is escaped",
			cfg:  commonConfig{Process: []string{`worker"one`}},
			want: `(process == "worker\"one")`,
		},
		{
			name: "backslash in process name is escaped",
			cfg:  commonConfig{Process: []string{`worker\one`}},
			want: `(process == "worker\\one")`,
		},
		{
			name: "quote and backslash in process name are escaped",
			cfg:  commonConfig{Process: []string{`a\b"c`}},
			want: `(process == "a\\b\"c")`,
		},
		{
			name: "predicates precede processes",
			cfg: commonConfig{
				Predicate: []string{"pid == 1"},
				Process:   []string{"sudo", "2"},
			},
			want: `(pid == 1) OR (process == "sudo") OR (processIdentifier == 2)`,
		},
		{
			name: "numeric-looking process name remains a name when out of range",
			cfg:  commonConfig{Process: []string{"2147483648"}},
			want: `(process == "2147483648")`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, buildNativePredicate(test.cfg), "native predicates should combine selectors with OR and escape process names")
		})
	}
}

func TestSourceConfigHashEquivalentSelectors(t *testing.T) {
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
	require.NoError(t, err, "a valid source configuration should produce a hash")
	require.Len(t, hash, 64, "source configuration hashes should be SHA-256 hex strings")

	reordered := base
	reordered.CommonConfig.Predicate = []string{"pid == 1", `process == "alpha"`}
	reordered.CommonConfig.Process = []string{"42", "beta"}
	reorderedHash, err := sourceConfigHash(reordered)
	require.NoError(t, err, "reordered selectors should produce a hash")
	assert.Equal(t, hash, reorderedHash, "selector ordering should not change an equivalent source configuration hash")
}

func TestSourceConfigHashChangesForSourceSettings(t *testing.T) {
	base := config{
		ShowConfig: showConfig{
			ArchiveFile: "/tmp/logs.logarchive",
			Start:       "2024-12-04",
			End:         "2024-12-05",
		},
		CommonConfig: commonConfig{
			Predicate: []string{"pid == 1"},
			Process:   []string{"beta"},
		},
	}

	baseHash, err := sourceConfigHash(base)
	require.NoError(t, err, "the base source configuration should hash successfully")

	tests := []struct {
		name   string
		mutate func(*config)
	}{
		{name: "archive file", mutate: func(cfg *config) { cfg.ShowConfig.ArchiveFile = "/tmp/other.logarchive" }},
		{name: "start", mutate: func(cfg *config) { cfg.ShowConfig.Start = "2024-12-03" }},
		{name: "end", mutate: func(cfg *config) { cfg.ShowConfig.End = "2024-12-06" }},
		{name: "predicate", mutate: func(cfg *config) { cfg.CommonConfig.Predicate = []string{"pid == 2"} }},
		{name: "process", mutate: func(cfg *config) { cfg.CommonConfig.Process = []string{"gamma"} }},
		{name: "info", mutate: func(cfg *config) { cfg.CommonConfig.Info = true }},
		{name: "debug", mutate: func(cfg *config) { cfg.CommonConfig.Debug = true }},
		{name: "signpost", mutate: func(cfg *config) { cfg.CommonConfig.Signpost = true }},
		{name: "backfill", mutate: func(cfg *config) { cfg.Backfill = true }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			test.mutate(&changed)
			changedHash, err := sourceConfigHash(changed)
			require.NoError(t, err, "a changed source configuration should hash successfully")
			assert.NotEqual(t, baseHash, changedHash, "changing %s should change the source configuration hash", test.name)
		})
	}
}

func TestParseConfiguredDate(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    time.Time
		wantErr string
		isZero  bool
	}{
		{name: "empty", value: "", isZero: true},
		{
			name:  "date only",
			value: "2024-12-04",
			want:  time.Date(2024, 12, 4, 0, 0, 0, 0, time.Local),
		},
		{
			name:  "local date time",
			value: "2024-12-04 13:46:00",
			want:  time.Date(2024, 12, 4, 13, 46, 0, 0, time.Local),
		},
		{
			name:  "offset date time",
			value: "2024-12-04 13:46:00+0200",
			want:  time.Date(2024, 12, 4, 13, 46, 0, 0, time.FixedZone("", 2*60*60)),
		},
		{
			name:    "invalid date",
			value:   "2024/12/04",
			wantErr: "not a valid date",
		},
		{
			name:    "RFC3339 is not accepted",
			value:   "2024-12-04T13:46:00Z",
			wantErr: "not a valid date",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseConfiguredDate(test.value)
			if test.wantErr != "" {
				require.Error(t, err, "invalid configured dates should fail parsing")
				assert.Contains(t, err.Error(), test.wantErr, "date parsing errors should describe the invalid value")
				return
			}
			require.NoError(t, err, "supported configured dates should parse successfully")
			if test.isZero {
				assert.True(t, got.IsZero(), "an empty configured date should return the zero time")
				return
			}
			assert.True(t, got.Equal(test.want), "configured date should represent the expected instant")
			assert.Equal(t, test.want.UnixNano(), got.UnixNano(), "configured date should preserve nanosecond precision")
		})
	}
}

func TestConfiguredTimeBounds(t *testing.T) {
	start, end, err := configuredTimeBounds(showConfig{
		Start: "2024-12-04",
		End:   "2024-12-05 13:46:00+0200",
	})
	require.NoError(t, err, "valid configured time bounds should parse successfully")
	assert.Equal(t, time.Date(2024, 12, 4, 0, 0, 0, 0, time.Local), start, "configured start should use the local location for date-only values")
	assert.Equal(t, time.Date(2024, 12, 5, 13, 46, 0, 0, time.FixedZone("", 2*60*60)), end, "configured end should preserve its explicit offset")

	_, _, err = configuredTimeBounds(showConfig{Start: "invalid"})
	require.Error(t, err, "an invalid start bound should fail parsing")
	assert.Contains(t, err.Error(), "parse start date", "start parsing errors should identify the start bound")

	_, _, err = configuredTimeBounds(showConfig{End: "invalid"})
	require.Error(t, err, "an invalid end bound should fail parsing")
	assert.Contains(t, err.Error(), "parse end date", "end parsing errors should identify the end bound")
}

func TestResumeStartUsesInclusiveOverlap(t *testing.T) {
	const highWaterMicros = int64(100_000_000)
	resume := cursorTime(highWaterMicros).Add(-cursorOverlap)

	tests := []struct {
		name       string
		state      cursorState
		configured time.Time
		want       time.Time
	}{
		{
			name:       "new cursor uses configured start",
			state:      newCursorState("source-hash"),
			configured: cursorTime(highWaterMicros - 20_000_000),
			want:       cursorTime(highWaterMicros - 20_000_000),
		},
		{
			name: "saved cursor starts at the inclusive five second overlap",
			state: cursorState{
				Version:          cursorVersion,
				HighWaterMicros:  highWaterMicros,
				SourceConfigHash: "source-hash",
			},
			want: resume,
		},
		{
			name: "configured start at overlap is retained",
			state: cursorState{
				Version:          cursorVersion,
				HighWaterMicros:  highWaterMicros,
				SourceConfigHash: "source-hash",
			},
			configured: resume,
			want:       resume,
		},
		{
			name: "configured start after overlap wins",
			state: cursorState{
				Version:          cursorVersion,
				HighWaterMicros:  highWaterMicros,
				SourceConfigHash: "source-hash",
			},
			configured: resume.Add(time.Microsecond),
			want:       resume.Add(time.Microsecond),
		},
		{
			name: "configured start before overlap does not move the resume earlier",
			state: cursorState{
				Version:          cursorVersion,
				HighWaterMicros:  highWaterMicros,
				SourceConfigHash: "source-hash",
			},
			configured: resume.Add(-time.Microsecond),
			want:       resume,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := resumeStart(test.state, test.configured)
			assert.Equal(t, test.want, got, "resume start should preserve the inclusive configured lower bound and overlap")
		})
	}
}

func TestBuildNativePredicateDoesNotMutateConfig(t *testing.T) {
	cfg := commonConfig{
		Predicate: []string{" second ", "first"},
		Process:   []string{" process "},
	}
	originalPredicates := append([]string(nil), cfg.Predicate...)
	originalProcesses := append([]string(nil), cfg.Process...)

	_ = buildNativePredicate(cfg)
	assert.Equal(t, originalPredicates, cfg.Predicate, "building a native predicate should not mutate configured predicates")
	assert.Equal(t, originalProcesses, cfg.Process, "building a native predicate should not mutate configured process selectors")
}

func TestQueryDateErrorListsAcceptedLayouts(t *testing.T) {
	_, err := parseConfiguredDate(strings.Repeat("x", 10))
	require.Error(t, err, "an invalid date should return a useful configuration error")
	for _, layout := range acceptedDateLayouts {
		assert.Contains(t, err.Error(), layout, "date parsing errors should list accepted layouts")
	}
}
