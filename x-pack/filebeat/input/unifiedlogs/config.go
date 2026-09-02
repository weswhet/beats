// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin

package unifiedlogs

import (
	"errors"
	"fmt"
	"strings"
	"time"

	conf "github.com/elastic/elastic-agent-libs/config"
)

type config struct {
	ShowConfig   showConfig   `config:",inline"`
	CommonConfig commonConfig `config:",inline"`
	Backfill     bool         `config:"backfill"`

	// unsupportedOptions records options that were explicitly present in the
	// configuration. Some of the legacy options are booleans, so their value
	// alone cannot distinguish an omitted option from an explicitly configured
	// false value.
	unsupportedOptions []string
}

type showConfig struct {
	ArchiveFile string `config:"archive_file"`
	TraceFile   string `config:"trace_file"`
	Start       string `config:"start"`
	End         string `config:"end"`
}

type commonConfig struct {
	Predicate          []string `config:"predicate"`
	Process            []string `config:"process"`
	Source             bool     `config:"source"`
	Info               bool     `config:"info"`
	Debug              bool     `config:"debug"`
	Backtrace          bool     `config:"backtrace"`
	Signpost           bool     `config:"signpost"`
	Unreliable         bool     `config:"unreliable"`
	MachContinuousTime bool     `config:"mach_continuous_time"`
}

// Unpack records explicitly configured legacy options before validating the
// native reader configuration. Keeping this separate from the public fields
// lets existing callers continue to construct config values directly.
func (c *config) Unpack(from *conf.C) error {
	type unpackConfig config
	decoded := unpackConfig(*c)
	decoded.unsupportedOptions = nil
	if err := from.Unpack(&decoded); err != nil {
		return err
	}

	*c = config(decoded)
	for _, option := range unsupportedConfigOptions {
		if from.HasField(option) {
			c.unsupportedOptions = append(c.unsupportedOptions, option)
		}
	}
	return nil
}

var unsupportedConfigOptions = []string{
	"trace_file",
	"source",
	"backtrace",
	"unreliable",
	"mach_continuous_time",
}

func (c config) Validate() error {
	if options := c.unsupportedOptionsForValidation(); len(options) > 0 {
		errs := make([]error, 0, len(options))
		for _, option := range options {
			errs = append(errs, fmt.Errorf("configuration option %q is not supported by the native macOS unified logs reader", option))
		}
		return errors.Join(errs...)
	}

	if err := checkDateFormat(c.ShowConfig.Start); err != nil {
		return fmt.Errorf("start date is not valid: %w", err)
	}
	if err := checkDateFormat(c.ShowConfig.End); err != nil {
		return fmt.Errorf("end date is not valid: %w", err)
	}
	if c.ShowConfig.ArchiveFile != "" && !strings.HasSuffix(c.ShowConfig.ArchiveFile, ".logarchive") {
		return fmt.Errorf("archive_file %v has the wrong extension", c.ShowConfig.ArchiveFile)
	}
	return nil
}

func (c config) unsupportedOptionsForValidation() []string {
	options := append([]string(nil), c.unsupportedOptions...)
	if c.ShowConfig.TraceFile != "" {
		options = appendIfMissing(options, "trace_file")
	}
	if c.CommonConfig.Source {
		options = appendIfMissing(options, "source")
	}
	if c.CommonConfig.Backtrace {
		options = appendIfMissing(options, "backtrace")
	}
	if c.CommonConfig.Unreliable {
		options = appendIfMissing(options, "unreliable")
	}
	if c.CommonConfig.MachContinuousTime {
		options = appendIfMissing(options, "mach_continuous_time")
	}
	return options
}

func appendIfMissing(options []string, option string) []string {
	for _, existing := range options {
		if existing == option {
			return options
		}
	}
	return append(options, option)
}

func defaultConfig() config {
	return config{}
}

func checkDateFormat(date string) error {
	if date == "" {
		return nil
	}
	acceptedLayouts := []string{
		"2006-01-02",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05-0700",
	}
	for _, layout := range acceptedLayouts {
		if _, err := time.Parse(layout, date); err == nil {
			return nil
		}
	}
	return fmt.Errorf("not a valid date, accepted layouts are: %v", acceptedLayouts)
}
