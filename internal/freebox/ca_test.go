// Copyright 2026 Lénaïc Huard
//
// Licensed under the MIT License, see LICENSE for details

package freebox

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertPool(t *testing.T) {
	require.NotNil(t, certPool, "certPool should be initialized")
	//nolint:staticcheck
	assert.Len(t, certPool.Subjects(), 2, "certPool should contain exactly 2 certificates")
}
