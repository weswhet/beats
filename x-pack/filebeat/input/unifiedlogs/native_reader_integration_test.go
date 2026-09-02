// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin && cgo

package unifiedlogs

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNativeStoreReadsCheckedInArchive(t *testing.T) {
	archivePath := extractTestLogArchive(t)
	reader, err := newNativeReader()
	require.NoError(t, err, "the Darwin cgo native reader should be available")

	events := make([]nativeEvent, 0, 461)
	err = reader.ReadStore(context.Background(), nativeQuery{
		ArchiveFile: archivePath,
		Info:        true,
		Debug:       true,
		Signpost:    true,
	}, func(event nativeEvent) error {
		events = append(events, event)
		return nil
	})
	require.NoError(t, err, "OSLogStore should read the checked-in log archive")
	for i, event := range events {
		assert.False(t, event.Timestamp.IsZero(), "archive event %d should have a native timestamp", i)
		assert.NotEqual(t, nativeKindUnknown, event.Kind, "archive event %d should map to a supported native kind", i)
	}
	// Repeated OSLogStore enumerations can vary by one decoded log entry for
	// this archive. Both native counts exclude the extra finished/count JSON
	// object emitted by the log CLI.
	require.Contains(t, []int{460, 461}, len(events), "OSLogStore should return only native archive entries, without the log CLI finished/count trailer")

	start := events[100].Timestamp
	end := events[200].Timestamp
	bounded := make([]nativeEvent, 0, 101)
	err = reader.ReadStore(context.Background(), nativeQuery{
		ArchiveFile: archivePath,
		Start:       start,
		End:         end,
		Info:        true,
		Debug:       true,
		Signpost:    true,
	}, func(event nativeEvent) error {
		bounded = append(bounded, event)
		return nil
	})
	require.NoError(t, err, "OSLogStore should apply an inclusive native date interval")
	require.NotEmpty(t, bounded, "the checked-in archive should contain events inside the selected interval")
	for i, event := range bounded {
		assert.False(t, event.Timestamp.Before(start), "bounded archive event %d must not precede the inclusive start", i)
		assert.False(t, event.Timestamp.After(end), "bounded archive event %d must not follow the inclusive end", i)
	}
}

func TestNativeStoreCancellation(t *testing.T) {
	archivePath := extractTestLogArchive(t)
	reader, err := newNativeReader()
	require.NoError(t, err, "the Darwin cgo native reader should be available")

	ctx, cancel := context.WithCancel(context.Background())
	seen := 0
	err = reader.ReadStore(ctx, nativeQuery{
		ArchiveFile: archivePath,
		Info:        true,
		Debug:       true,
		Signpost:    true,
	}, func(nativeEvent) error {
		seen++
		cancel()
		return nil
	})
	assert.ErrorIs(t, err, context.Canceled, "canceling an active Store enumeration should stop the native bridge")
	assert.Positive(t, seen, "the Store should emit an event before the test cancels it")
}

func TestNativeStoreRejectsMissingPredicateArguments(t *testing.T) {
	archivePath := extractTestLogArchive(t)
	reader, err := newNativeReader()
	require.NoError(t, err, "the Darwin cgo native reader should be available")

	err = reader.ReadStore(context.Background(), nativeQuery{
		ArchiveFile: archivePath,
		Predicate:   "%@",
	}, func(nativeEvent) error { return nil })
	require.Error(t, err, "a predicate with an unbound format placeholder should fail without invoking undefined varargs behavior")
}

func TestNativePrivateStreamWhenExplicitlyEnabled(t *testing.T) {
	if os.Getenv("FILEBEAT_UNIFIEDLOGS_PRIVATE_STREAM_TEST") != "1" {
		t.Skip("set FILEBEAT_UNIFIEDLOGS_PRIVATE_STREAM_TEST=1 in an administrator, unsandboxed session")
	}

	reader, err := newNativeReader()
	require.NoError(t, err, "the Darwin cgo native reader should be available")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := 0
	usableEvents := 0
	err = reader.Stream(ctx, nativeQuery{}, func(event nativeEvent) error {
		events++
		if !event.Timestamp.IsZero() && event.Kind != nativeKindUnknown {
			usableEvents++
		}
		return nil
	})
	require.ErrorIs(t, err, context.DeadlineExceeded, "an explicitly enabled private stream should remain active until canceled")
	assert.Positive(t, events, "the explicitly enabled private stream should deliver at least one native event")
	assert.Positive(t, usableEvents, "the explicitly enabled private stream should deliver at least one usable native event")
}

func extractTestLogArchive(t *testing.T) string {
	t.Helper()

	file, err := os.Open(filepath.Join("testdata", "test.logarchive.tar.gz"))
	require.NoError(t, err, "the checked-in log archive fixture should open")
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	require.NoError(t, err, "the checked-in log archive fixture should be gzip-compressed")
	defer gzipReader.Close()

	destination := t.TempDir()
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err, "the checked-in log archive tar stream should be readable")

		cleanName := filepath.Clean(header.Name)
		require.False(t, filepath.IsAbs(cleanName), "archive fixture entries must be relative")
		require.False(t, cleanName == ".." || strings.HasPrefix(cleanName, ".."+string(filepath.Separator)), "archive fixture entries must stay inside the test directory")
		target := filepath.Join(destination, cleanName)
		switch header.Typeflag {
		case tar.TypeDir:
			require.NoError(t, os.MkdirAll(target, 0o755), "archive fixture directories should be created")
		case tar.TypeReg:
			require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755), "archive fixture parent directories should be created")
			output, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode))
			require.NoError(t, err, "archive fixture files should be created")
			_, copyErr := io.Copy(output, tarReader)
			closeErr := output.Close()
			require.NoError(t, copyErr, "archive fixture file contents should be extracted")
			require.NoError(t, closeErr, "archive fixture files should close cleanly")
		}
	}

	archivePath := filepath.Join(destination, "test.logarchive")
	info, err := os.Stat(archivePath)
	require.NoError(t, err, "the extracted fixture should contain test.logarchive")
	require.True(t, info.IsDir(), "the extracted test.logarchive should be a bundle directory")
	return archivePath
}
