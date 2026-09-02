// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin

package unifiedlogs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	conf "github.com/elastic/elastic-agent-libs/config"
)

func TestConfigUnpack(t *testing.T) {
	const cfgYAML = `
archive_file: /path/to/file.logarchive
start: 2024-12-04 13:46:00+0200
end: 2024-12-04 13:46:00+0200
predicate:
- pid == 1
- process == "sudo"
process:
- sudo
- 42
info: true
debug: true
signpost: true
backfill: true
`

	c := conf.MustNewConfigFrom(cfgYAML)
	cfg := defaultConfig()
	err := c.Unpack(&cfg)
	require.NoError(t, err, "supported unifiedlogs settings should unpack")

	assert.Equal(t, "/path/to/file.logarchive", cfg.ShowConfig.ArchiveFile, "archive_file should be preserved")
	assert.Equal(t, "2024-12-04 13:46:00+0200", cfg.ShowConfig.Start, "start should be preserved")
	assert.Equal(t, "2024-12-04 13:46:00+0200", cfg.ShowConfig.End, "end should be preserved")
	assert.Equal(t, []string{"pid == 1", `process == "sudo"`}, cfg.CommonConfig.Predicate, "predicates should be preserved in order")
	assert.Equal(t, []string{"sudo", "42"}, cfg.CommonConfig.Process, "process selectors should be preserved in order")
	assert.True(t, cfg.CommonConfig.Info, "info should be enabled")
	assert.True(t, cfg.CommonConfig.Debug, "debug should be enabled")
	assert.True(t, cfg.CommonConfig.Signpost, "signpost should be enabled")
	assert.True(t, cfg.Backfill, "backfill should be enabled")
}

func TestConfigRejectsUnsupportedOptions(t *testing.T) {
	tests := []struct {
		name   string
		config string
		option string
	}{
		{name: "trace file", config: "trace_file: /path/to/file.tracev3\n", option: "trace_file"},
		{name: "empty trace file", config: "trace_file: ''\n", option: "trace_file"},
		{name: "source", config: "source: true\n", option: "source"},
		{name: "backtrace", config: "backtrace: true\n", option: "backtrace"},
		{name: "unreliable", config: "unreliable: true\n", option: "unreliable"},
		{name: "mach continuous time", config: "mach_continuous_time: true\n", option: "mach_continuous_time"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := defaultConfig()
			err := conf.MustNewConfigFrom(test.config).Unpack(&cfg)
			require.Error(t, err, "legacy option should be rejected")
			assert.Contains(t, err.Error(), test.option, "error should name the rejected option")
		})
	}
}

func TestConfigRejectsAllUnsupportedOptionsWithNames(t *testing.T) {
	const cfgYAML = `
trace_file: /path/to/file.tracev3
source: false
backtrace: false
unreliable: false
mach_continuous_time: false
`

	cfg := defaultConfig()
	err := conf.MustNewConfigFrom(cfgYAML).Unpack(&cfg)
	require.Error(t, err, "legacy unifiedlogs options should be rejected")
	for _, option := range unsupportedConfigOptions {
		assert.Contains(t, err.Error(), option, "combined validation error should name every rejected option")
	}
}

func TestConfigRejectsExplicitFalseUnsupportedOptions(t *testing.T) {
	for _, option := range []string{"source", "backtrace", "unreliable", "mach_continuous_time"} {
		t.Run(option, func(t *testing.T) {
			cfg := defaultConfig()
			err := conf.MustNewConfigFrom(option + ": false\n").Unpack(&cfg)
			require.Error(t, err, "explicitly configured legacy option should be rejected")
			assert.Contains(t, err.Error(), option, "error should name the rejected option")
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  config
		wantErr string
	}{
		{
			name: "archive extension",
			config: config{ShowConfig: showConfig{
				ArchiveFile: "/path/to/file.tracev3",
			}},
			wantErr: "archive_file",
		},
		{
			name: "start date",
			config: config{ShowConfig: showConfig{
				Start: "2024-13-01",
			}},
			wantErr: "start date is not valid",
		},
		{
			name: "end date",
			config: config{ShowConfig: showConfig{
				End: "not-a-date",
			}},
			wantErr: "end date is not valid",
		},
		{
			name: "valid date layouts",
			config: config{ShowConfig: showConfig{
				Start: "2024-12-04",
				End:   "2024-12-04 13:46:00-0700",
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.config.Validate()
			if test.wantErr == "" {
				require.NoError(t, err, "valid unifiedlogs configuration should pass validation")
				return
			}
			require.Error(t, err, "invalid unifiedlogs configuration should fail validation")
			assert.True(t, strings.Contains(err.Error(), test.wantErr), "validation error %q should contain %q", err, test.wantErr)
		})
	}
}

func TestCheckDateFormat(t *testing.T) {
	tests := []struct {
		date    string
		valid   bool
		message string
	}{
		{date: "", valid: true, message: "empty dates are optional"},
		{date: "2024-12-04", valid: true, message: "date-only values are supported"},
		{date: "2024-12-04 13:46:00", valid: true, message: "local date-time values are supported"},
		{date: "2024-12-04 13:46:00+0200", valid: true, message: "offset date-time values are supported"},
		{date: "2024/12/04", valid: false, message: "slash-separated dates are not supported"},
		{date: "2024-12-04T13:46:00Z", valid: false, message: "RFC3339 dates are not part of the input contract"},
	}

	for _, test := range tests {
		t.Run(test.date, func(t *testing.T) {
			err := checkDateFormat(test.date)
			if test.valid {
				require.NoError(t, err, test.message)
			} else {
				require.Error(t, err, test.message)
			}
		})
	}
}
