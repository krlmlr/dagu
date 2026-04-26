// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func computeSig(t *testing.T, secret, body string) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	_, err := mac.Write([]byte(body))
	require.NoError(t, err)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyWebhookHMAC_NotConfigured(t *testing.T) {
	t.Parallel()
	w := &Webhook{}
	headers := http.Header{}
	headers.Set("X-Hub-Signature-256", "anything")
	require.NoError(t, VerifyWebhookHMAC(w, headers, []byte("body")))
}

func TestVerifyWebhookHMAC_NilWebhook(t *testing.T) {
	t.Parallel()
	require.NoError(t, VerifyWebhookHMAC(nil, http.Header{}, []byte("body")))
}

func TestVerifyWebhookHMAC_GitHubStyle(t *testing.T) {
	t.Parallel()
	body := []byte(`{"hello":"world"}`)
	secret := "topsecret-1234567"

	// GitHub-style configuration (the platform default, but here set
	// explicitly because the verifier reads stored fields verbatim).
	w := &Webhook{
		HMACSecret: secret,
		HMACHeader: DefaultHMACHeader,
		HMACPrefix: DefaultHMACPrefix,
	}
	headers := http.Header{}
	headers.Set(DefaultHMACHeader, DefaultHMACPrefix+computeSig(t, secret, string(body)))

	require.NoError(t, VerifyWebhookHMAC(w, headers, body))
}

func TestVerifyWebhookHMAC_CustomHeaderEmptyPrefix(t *testing.T) {
	t.Parallel()
	body := []byte("payload-bytes")
	secret := "another-secret-value"

	// Gitea-style: "X-Gitea-Signature" with empty prefix (the bare hex digest).
	// HMACPrefix is read verbatim by the verifier, so an explicitly-empty
	// string means "no prefix" and is distinct from the platform default.
	w := &Webhook{
		HMACSecret: secret,
		HMACHeader: "X-Gitea-Signature",
		HMACPrefix: "",
	}

	headers := http.Header{}
	headers.Set("X-Gitea-Signature", computeSig(t, secret, string(body)))
	require.NoError(t, VerifyWebhookHMAC(w, headers, body))
}

func TestVerifyWebhookHMAC_StoredPrefixMustMatch(t *testing.T) {
	t.Parallel()
	// The verifier reads HMACPrefix verbatim. A record persisted with
	// "sha256=" rejects bare hex digests.
	body := []byte("payload")
	secret := "secret-1234567890"

	w := &Webhook{
		HMACSecret: secret,
		HMACHeader: "X-Sig",
		HMACPrefix: "sha256=",
	}
	headers := http.Header{}
	headers.Set("X-Sig", computeSig(t, secret, string(body)))

	assert.ErrorIs(t, VerifyWebhookHMAC(w, headers, body), ErrInvalidWebhookSignature)
}

// githubStyleWebhook returns a webhook configured for GitHub-style HMAC,
// matching what the API handler would persist for a default configuration.
func githubStyleWebhook(secret string) *Webhook {
	return &Webhook{
		HMACSecret: secret,
		HMACHeader: DefaultHMACHeader,
		HMACPrefix: DefaultHMACPrefix,
	}
}

func TestVerifyWebhookHMAC_MissingHeader(t *testing.T) {
	t.Parallel()
	w := githubStyleWebhook("secret-1234567890")
	require.ErrorIs(t,
		VerifyWebhookHMAC(w, http.Header{}, []byte("body")),
		ErrInvalidWebhookSignature,
	)
}

func TestVerifyWebhookHMAC_WrongPrefix(t *testing.T) {
	t.Parallel()
	body := []byte("body")
	secret := "secret-1234567890"
	w := githubStyleWebhook(secret)
	headers := http.Header{}
	headers.Set("X-Hub-Signature-256", "sha1="+computeSig(t, secret, string(body)))
	require.ErrorIs(t, VerifyWebhookHMAC(w, headers, body), ErrInvalidWebhookSignature)
}

func TestVerifyWebhookHMAC_NonHexValue(t *testing.T) {
	t.Parallel()
	w := githubStyleWebhook("secret-1234567890")
	headers := http.Header{}
	headers.Set("X-Hub-Signature-256", "sha256=not-a-hex-digest!!")
	require.ErrorIs(t, VerifyWebhookHMAC(w, headers, []byte("body")), ErrInvalidWebhookSignature)
}

func TestVerifyWebhookHMAC_DigestMismatch(t *testing.T) {
	t.Parallel()
	body := []byte("body")
	w := githubStyleWebhook("secret-1234567890")
	// Compute over a different body to force a mismatch.
	wrong := computeSig(t, "secret-1234567890", "different-body")
	headers := http.Header{}
	headers.Set("X-Hub-Signature-256", "sha256="+wrong)
	require.ErrorIs(t, VerifyWebhookHMAC(w, headers, body), ErrInvalidWebhookSignature)
}

func TestVerifyWebhookHMAC_BodyTamperRegression(t *testing.T) {
	t.Parallel()
	secret := "secret-1234567890"
	original := []byte(`{"event":"push","ref":"main"}`)
	tampered := []byte(`{"event":"push","ref":"prod"}`)

	sig := computeSig(t, secret, string(original))
	headers := http.Header{}
	headers.Set("X-Hub-Signature-256", "sha256="+sig)

	w := githubStyleWebhook(secret)
	require.NoError(t, VerifyWebhookHMAC(w, headers, original))
	require.ErrorIs(t, VerifyWebhookHMAC(w, headers, tampered), ErrInvalidWebhookSignature)
}

func TestVerifyWebhookHMAC_UnsupportedAlgorithm(t *testing.T) {
	t.Parallel()
	w := &Webhook{
		HMACSecret:    "secret-1234567890",
		HMACAlgorithm: "md5",
		HMACHeader:    DefaultHMACHeader,
		HMACPrefix:    DefaultHMACPrefix,
	}
	headers := http.Header{}
	headers.Set("X-Hub-Signature-256", "sha256=deadbeef")
	require.ErrorIs(t,
		VerifyWebhookHMAC(w, headers, []byte("body")),
		ErrUnsupportedWebhookHMACAlgorithm,
	)
}

func TestVerifyWebhookHMAC_HeaderCaseInsensitive(t *testing.T) {
	t.Parallel()
	body := []byte("body")
	secret := "secret-1234567890"
	w := githubStyleWebhook(secret)

	headers := http.Header{}
	// Set with non-canonical case; http.Header.Get is canonicalized.
	headers.Set("x-hub-signature-256", "sha256="+computeSig(t, secret, string(body)))
	require.NoError(t, VerifyWebhookHMAC(w, headers, body))
}

func TestWebhook_HMACDefaults(t *testing.T) {
	t.Parallel()
	w := &Webhook{}
	// Algorithm and header fall back to the platform defaults when empty
	// (used for displaying older records / records mid-migration).
	assert.Equal(t, DefaultHMACAlgorithm, w.HMACAlgorithmOrDefault())
	assert.Equal(t, DefaultHMACHeader, w.HMACHeaderOrDefault())
	// Prefix is returned verbatim — empty means "no prefix".
	assert.Equal(t, "", w.HMACPrefixOrDefault())

	w2 := &Webhook{
		HMACAlgorithm: "SHA256",
		HMACHeader:    "X-Stripe-Signature",
		HMACPrefix:    "v1=",
	}
	assert.Equal(t, "SHA256", w2.HMACAlgorithmOrDefault())
	assert.Equal(t, "X-Stripe-Signature", w2.HMACHeaderOrDefault())
	assert.Equal(t, "v1=", w2.HMACPrefixOrDefault())

	assert.False(t, w.HMACEnabled())
	w.HMACSecret = "x"
	assert.True(t, w.HMACEnabled())
}
