// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build darwin && !cgo

package unifiedlogs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNativeReaderWithoutCgoIsExplicitlyUnsupported(t *testing.T) {
	reader, err := newNativeReader()
	assert.Nil(t, reader, "a Darwin build without cgo must not construct a native reader")
	assert.ErrorIs(t, err, errNativeReaderUnsupported, "a Darwin build without cgo should return a clear unsupported error")
}
