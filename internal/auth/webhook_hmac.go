// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"net/http"
	"strings"
)

const (
	// DefaultHMACAlgorithm is used when Webhook.HMACAlgorithm is empty.
	DefaultHMACAlgorithm = "sha256"
	// DefaultHMACHeader is used when Webhook.HMACHeader is empty.
	// Matches the header used by GitHub for webhook deliveries.
	DefaultHMACHeader = "X-Hub-Signature-256"
	// DefaultHMACPrefix is used when Webhook.HMACPrefix is empty.
	// Matches the prefix used by GitHub.
	DefaultHMACPrefix = "sha256="
)

// HMACAlgorithmOrDefault reports the algorithm to use for verification,
// applying the default when none is configured. Used for display/UI; the
// service layer resolves and persists the concrete value at configuration
// time, so verification reads the stored value verbatim.
func (w *Webhook) HMACAlgorithmOrDefault() string {
	if w == nil || w.HMACAlgorithm == "" {
		return DefaultHMACAlgorithm
	}
	return w.HMACAlgorithm
}

// HMACHeaderOrDefault reports the header name to read the signature from,
// applying the default when none is configured. Used for display/UI.
func (w *Webhook) HMACHeaderOrDefault() string {
	if w == nil || w.HMACHeader == "" {
		return DefaultHMACHeader
	}
	return w.HMACHeader
}

// HMACPrefixOrDefault reports the prefix to strip from the signature header
// value. Returns the configured prefix verbatim so an explicitly-empty
// prefix (Gitea-style) is not silently replaced with the GitHub default.
// The service layer resolves "no value supplied at config time" to the
// platform default before persisting, so any record reaching this path has
// an intentional value.
func (w *Webhook) HMACPrefixOrDefault() string {
	if w == nil {
		return DefaultHMACPrefix
	}
	return w.HMACPrefix
}

// VerifyWebhookHMAC validates the inbound request body against the HMAC
// configuration on the webhook.
//
// When HMAC is not configured (HMACSecret is empty), it returns nil so the
// caller can invoke it unconditionally on every delivery.
//
// When HMAC is configured, it reads the signature header from headers,
// strips the configured prefix, hex-decodes the remainder, and compares the
// decoded bytes against HMAC-Algorithm(body, secret) using a constant-time
// comparison. Any failure returns ErrInvalidWebhookSignature; the caller
// should not distinguish between failure modes when responding to the client
// to avoid leaking validation internals.
func VerifyWebhookHMAC(w *Webhook, headers http.Header, body []byte) error {
	if !w.HMACEnabled() {
		return nil
	}

	hashFn, err := hmacHashFn(w.HMACAlgorithmOrDefault())
	if err != nil {
		return err
	}

	headerValue := headers.Get(w.HMACHeaderOrDefault())
	if headerValue == "" {
		return ErrInvalidWebhookSignature
	}

	// Read the configured prefix verbatim — an explicitly-empty prefix
	// means "no prefix", so we must not fall back to the default here.
	digestHex, ok := strings.CutPrefix(headerValue, w.HMACPrefix)
	if !ok {
		return ErrInvalidWebhookSignature
	}

	provided, err := hex.DecodeString(strings.TrimSpace(digestHex))
	if err != nil {
		return ErrInvalidWebhookSignature
	}

	mac := hmac.New(hashFn, []byte(w.HMACSecret))
	mac.Write(body)
	expected := mac.Sum(nil)

	if !hmac.Equal(expected, provided) {
		return ErrInvalidWebhookSignature
	}
	return nil
}

// hmacHashFn returns the constructor for the supported HMAC algorithm.
func hmacHashFn(algorithm string) (func() hash.Hash, error) {
	switch strings.ToLower(algorithm) {
	case "", DefaultHMACAlgorithm:
		return sha256.New, nil
	default:
		return nil, ErrUnsupportedWebhookHMACAlgorithm
	}
}
