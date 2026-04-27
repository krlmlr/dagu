// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/dagucloud/dagu/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_SetWebhookHMAC(t *testing.T) {
	t.Parallel()

	t.Run("StoresValuesVerbatim", func(t *testing.T) {
		t.Parallel()
		service, _ := setupWebhookTestService(t)
		ctx := context.Background()

		_, err := service.CreateWebhook(ctx, "dag.yaml", "creator")
		require.NoError(t, err)

		// The service stores fields verbatim; default resolution is the
		// caller's responsibility (the API handler resolves them at
		// configure time so persisted records are self-describing).
		wh, err := service.SetWebhookHMAC(ctx, "dag.yaml", HMACConfig{
			Secret: "0123456789abcdef-secret",
		})
		require.NoError(t, err)
		assert.True(t, wh.HMACEnabled())
		assert.Empty(t, wh.HMACAlgorithm)
		assert.Empty(t, wh.HMACHeader)
		assert.Empty(t, wh.HMACPrefix)
	})

	t.Run("ValidCustomConfig", func(t *testing.T) {
		t.Parallel()
		service, _ := setupWebhookTestService(t)
		ctx := context.Background()

		_, err := service.CreateWebhook(ctx, "dag.yaml", "creator")
		require.NoError(t, err)

		wh, err := service.SetWebhookHMAC(ctx, "dag.yaml", HMACConfig{
			Secret:    "0123456789abcdef-secret",
			Algorithm: "sha256",
			Header:    "X-Gitea-Signature",
			Prefix:    "",
		})
		require.NoError(t, err)
		assert.True(t, wh.HMACEnabled())
		assert.Equal(t, "X-Gitea-Signature", wh.HMACHeader)
	})

	t.Run("ReplacesExistingConfig", func(t *testing.T) {
		t.Parallel()
		service, _ := setupWebhookTestService(t)
		ctx := context.Background()

		_, err := service.CreateWebhook(ctx, "dag.yaml", "creator")
		require.NoError(t, err)

		_, err = service.SetWebhookHMAC(ctx, "dag.yaml", HMACConfig{
			Secret: "0123456789abcdef-secret",
			Header: "X-Hub-Signature-256",
		})
		require.NoError(t, err)

		wh, err := service.SetWebhookHMAC(ctx, "dag.yaml", HMACConfig{
			Secret: "rotated-secret-1234567",
			Header: "X-Other-Signature",
		})
		require.NoError(t, err)
		assert.Equal(t, "rotated-secret-1234567", wh.HMACSecret)
		assert.Equal(t, "X-Other-Signature", wh.HMACHeader)
	})

	t.Run("WebhookNotFound", func(t *testing.T) {
		t.Parallel()
		service, _ := setupWebhookTestService(t)
		ctx := context.Background()
		_, err := service.SetWebhookHMAC(ctx, "missing.yaml", HMACConfig{
			Secret: "0123456789abcdef-secret",
		})
		assert.ErrorIs(t, err, auth.ErrWebhookNotFound)
	})

	t.Run("RejectsShortSecret", func(t *testing.T) {
		t.Parallel()
		service, _ := setupWebhookTestService(t)
		ctx := context.Background()
		_, err := service.CreateWebhook(ctx, "dag.yaml", "creator")
		require.NoError(t, err)

		_, err = service.SetWebhookHMAC(ctx, "dag.yaml", HMACConfig{Secret: "tooshort"})
		assert.ErrorIs(t, err, ErrInvalidHMACSecret)
	})

	t.Run("RejectsLongSecret", func(t *testing.T) {
		t.Parallel()
		service, _ := setupWebhookTestService(t)
		ctx := context.Background()
		_, err := service.CreateWebhook(ctx, "dag.yaml", "creator")
		require.NoError(t, err)

		_, err = service.SetWebhookHMAC(ctx, "dag.yaml", HMACConfig{Secret: strings.Repeat("a", maxHMACSecretBytes+1)})
		assert.ErrorIs(t, err, ErrInvalidHMACSecret)
	})

	t.Run("RejectsBadAlgorithm", func(t *testing.T) {
		t.Parallel()
		service, _ := setupWebhookTestService(t)
		ctx := context.Background()
		_, err := service.CreateWebhook(ctx, "dag.yaml", "creator")
		require.NoError(t, err)

		_, err = service.SetWebhookHMAC(ctx, "dag.yaml", HMACConfig{
			Secret:    "0123456789abcdef-secret",
			Algorithm: "md5",
		})
		assert.ErrorIs(t, err, ErrInvalidHMACAlgorithm)
	})

	t.Run("RejectsBadHeader", func(t *testing.T) {
		t.Parallel()
		service, _ := setupWebhookTestService(t)
		ctx := context.Background()
		_, err := service.CreateWebhook(ctx, "dag.yaml", "creator")
		require.NoError(t, err)

		// Contains a colon which is not in the [A-Za-z0-9-] charset.
		_, err = service.SetWebhookHMAC(ctx, "dag.yaml", HMACConfig{
			Secret: "0123456789abcdef-secret",
			Header: "X-Hub:Signature",
		})
		assert.ErrorIs(t, err, ErrInvalidHMACHeader)
	})

	t.Run("RejectsHeaderTooLong", func(t *testing.T) {
		t.Parallel()
		service, _ := setupWebhookTestService(t)
		ctx := context.Background()
		_, err := service.CreateWebhook(ctx, "dag.yaml", "creator")
		require.NoError(t, err)

		_, err = service.SetWebhookHMAC(ctx, "dag.yaml", HMACConfig{
			Secret: "0123456789abcdef-secret",
			Header: strings.Repeat("X", maxHMACHeaderLen+1),
		})
		assert.ErrorIs(t, err, ErrInvalidHMACHeader)
	})

	t.Run("RejectsPrefixTooLong", func(t *testing.T) {
		t.Parallel()
		service, _ := setupWebhookTestService(t)
		ctx := context.Background()
		_, err := service.CreateWebhook(ctx, "dag.yaml", "creator")
		require.NoError(t, err)

		_, err = service.SetWebhookHMAC(ctx, "dag.yaml", HMACConfig{
			Secret: "0123456789abcdef-secret",
			Prefix: strings.Repeat("p", maxHMACPrefixLen+1),
		})
		assert.ErrorIs(t, err, ErrInvalidHMACPrefix)
	})
}

func TestService_ClearWebhookHMAC(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		service, _ := setupWebhookTestService(t)
		ctx := context.Background()

		_, err := service.CreateWebhook(ctx, "dag.yaml", "creator")
		require.NoError(t, err)

		_, err = service.SetWebhookHMAC(ctx, "dag.yaml", HMACConfig{
			Secret: "0123456789abcdef-secret",
		})
		require.NoError(t, err)

		wh, err := service.ClearWebhookHMAC(ctx, "dag.yaml")
		require.NoError(t, err)
		assert.False(t, wh.HMACEnabled())
		assert.Empty(t, wh.HMACSecret)
		assert.Empty(t, wh.HMACHeader)
	})

	t.Run("WebhookNotFound", func(t *testing.T) {
		t.Parallel()
		service, _ := setupWebhookTestService(t)
		ctx := context.Background()
		_, err := service.ClearWebhookHMAC(ctx, "missing.yaml")
		assert.ErrorIs(t, err, auth.ErrWebhookNotFound)
	})

	t.Run("ServiceWithoutWebhookStore", func(t *testing.T) {
		t.Parallel()
		service := New(nil, Config{
			TokenSecret: mustTokenSecret("test"),
		})
		_, err := service.ClearWebhookHMAC(context.Background(), "dag.yaml")
		assert.ErrorIs(t, err, ErrWebhookNotConfigured)

		_, err = service.SetWebhookHMAC(context.Background(), "dag.yaml", HMACConfig{
			Secret: "0123456789abcdef-secret",
		})
		assert.ErrorIs(t, err, ErrWebhookNotConfigured)
	})
}
