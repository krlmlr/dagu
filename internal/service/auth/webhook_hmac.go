// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/dagucloud/dagu/internal/auth"
)

const (
	// minHMACSecretBytes guards against trivially weak symmetric keys.
	minHMACSecretBytes = 16
	// maxHMACSecretBytes is a sanity upper bound on the key size.
	maxHMACSecretBytes = 4096
	// maxHMACHeaderLen caps the configurable header name length.
	maxHMACHeaderLen = 128
	// maxHMACPrefixLen caps the configurable signature prefix length.
	maxHMACPrefixLen = 32
)

// hmacHeaderPattern restricts header names to the RFC 7230 token characters
// we actually want to accept. We do not allow ":", quoted strings, etc., to
// keep the configuration channel free of surprises.
var hmacHeaderPattern = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// HMACConfig is the input for SetWebhookHMAC. Fields with empty defaults
// fall back to the platform defaults at verification time.
type HMACConfig struct {
	Secret    string
	Algorithm string
	Header    string
	Prefix    string
}

// SetWebhookHMAC configures HMAC verification for the given DAG's webhook,
// replacing any previous configuration. Validation enforces:
//   - secret length 16..4096 bytes
//   - algorithm in {"", "sha256"}
//   - header matches [A-Za-z0-9-]+, length 1..128 (when set)
//   - prefix length <=32 (when set)
//
// On success the updated webhook is returned. The webhook's UpdatedAt
// timestamp is bumped.
func (s *Service) SetWebhookHMAC(ctx context.Context, dagName string, cfg HMACConfig) (*auth.Webhook, error) {
	if s.webhookStore == nil {
		return nil, ErrWebhookNotConfigured
	}

	if err := validateHMACConfig(cfg); err != nil {
		return nil, err
	}

	webhook, err := s.webhookStore.GetByDAGName(ctx, dagName)
	if err != nil {
		return nil, err
	}

	webhook.HMACSecret = cfg.Secret
	webhook.HMACAlgorithm = strings.ToLower(strings.TrimSpace(cfg.Algorithm))
	webhook.HMACHeader = strings.TrimSpace(cfg.Header)
	webhook.HMACPrefix = cfg.Prefix
	webhook.UpdatedAt = time.Now().UTC()

	if err := s.webhookStore.Update(ctx, webhook); err != nil {
		return nil, err
	}

	return webhook, nil
}

// ClearWebhookHMAC removes the HMAC configuration from the webhook, returning
// it to bearer-only authentication. UpdatedAt is bumped on success.
func (s *Service) ClearWebhookHMAC(ctx context.Context, dagName string) (*auth.Webhook, error) {
	if s.webhookStore == nil {
		return nil, ErrWebhookNotConfigured
	}

	webhook, err := s.webhookStore.GetByDAGName(ctx, dagName)
	if err != nil {
		return nil, err
	}

	webhook.HMACSecret = ""
	webhook.HMACAlgorithm = ""
	webhook.HMACHeader = ""
	webhook.HMACPrefix = ""
	webhook.UpdatedAt = time.Now().UTC()

	if err := s.webhookStore.Update(ctx, webhook); err != nil {
		return nil, err
	}

	return webhook, nil
}

func validateHMACConfig(cfg HMACConfig) error {
	if l := len(cfg.Secret); l < minHMACSecretBytes || l > maxHMACSecretBytes {
		return ErrInvalidHMACSecret
	}

	switch strings.ToLower(strings.TrimSpace(cfg.Algorithm)) {
	case "", auth.DefaultHMACAlgorithm:
	default:
		return ErrInvalidHMACAlgorithm
	}

	if h := strings.TrimSpace(cfg.Header); h != "" {
		if len(h) > maxHMACHeaderLen || !hmacHeaderPattern.MatchString(h) {
			return ErrInvalidHMACHeader
		}
	}

	if len(cfg.Prefix) > maxHMACPrefixLen {
		return ErrInvalidHMACPrefix
	}

	return nil
}
