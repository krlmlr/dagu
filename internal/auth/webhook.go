// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"time"

	"github.com/google/uuid"
)

// Webhook represents a webhook configuration for triggering a specific DAG.
// Each DAG can have at most one webhook. The token is stored as a bcrypt hash.
type Webhook struct {
	// ID is the unique identifier for the webhook (UUID).
	ID string `json:"id"`
	// DAGName is the file name of the DAG this webhook triggers.
	// This serves as a unique constraint - one webhook per DAG.
	DAGName string `json:"dagName"`
	// TokenHash is the bcrypt hash of the webhook token secret.
	// Excluded from JSON serialization for security.
	TokenHash string `json:"-"`
	// TokenPrefix stores the first 8 characters of the token for identification.
	TokenPrefix string `json:"tokenPrefix"`
	// Enabled indicates whether the webhook is active.
	Enabled bool `json:"enabled"`
	// CreatedAt is the timestamp when the webhook was created.
	CreatedAt time.Time `json:"createdAt"`
	// UpdatedAt is the timestamp when the webhook was last modified.
	UpdatedAt time.Time `json:"updatedAt"`
	// CreatedBy is the user ID of the admin who created the webhook.
	CreatedBy string `json:"createdBy"`
	// LastUsedAt is the timestamp when the webhook was last triggered.
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`

	// HMACSecret is the symmetric secret used to verify the inbound request
	// body via HMAC. When empty, HMAC verification is disabled and the bearer
	// token is the only authentication. When non-empty, the verifier reads
	// the configured signature header, strips the configured prefix, hex-decodes
	// the value, and compares it to HMAC-Algorithm(rawBody, secret) in
	// constant time.
	// Excluded from JSON serialization for security.
	HMACSecret string `json:"-"`
	// HMACAlgorithm is the hash algorithm used for HMAC. "" or "sha256"
	// selects SHA-256. Reserved for future extension.
	HMACAlgorithm string `json:"hmacAlgorithm,omitempty"`
	// HMACHeader is the HTTP header to read the signature from
	// (case-insensitive). When empty, defaults to "X-Hub-Signature-256".
	HMACHeader string `json:"hmacHeader,omitempty"`
	// HMACPrefix is stripped from the signature header value before hex
	// decoding. When empty, defaults to "sha256=". Use a single space ("\x00")
	// or set to the literal empty string for providers that send a bare hex
	// digest.
	HMACPrefix string `json:"hmacPrefix,omitempty"`
}

// HMACEnabled reports whether HMAC verification is configured for this webhook.
func (w *Webhook) HMACEnabled() bool {
	return w != nil && w.HMACSecret != ""
}

// NewWebhook creates a Webhook with a new UUID and sets CreatedAt and UpdatedAt to the current UTC time.
// It validates that required fields are not empty.
// Returns an error if validation fails.
func NewWebhook(dagName, tokenHash, tokenPrefix, createdBy string) (*Webhook, error) {
	if dagName == "" {
		return nil, ErrInvalidWebhookDAGName
	}
	if tokenHash == "" {
		return nil, ErrInvalidWebhookTokenHash
	}
	now := time.Now().UTC()
	return &Webhook{
		ID:          uuid.New().String(),
		DAGName:     dagName,
		TokenHash:   tokenHash,
		TokenPrefix: tokenPrefix,
		Enabled:     true, // Enabled by default on creation
		CreatedAt:   now,
		UpdatedAt:   now,
		CreatedBy:   createdBy,
	}, nil
}

// WebhookForStorage is used for JSON serialization to persistent storage.
// It includes the token hash which is excluded from the regular Webhook JSON.
type WebhookForStorage struct {
	ID          string     `json:"id"`
	DAGName     string     `json:"dagName"`
	TokenHash   string     `json:"tokenHash"`
	TokenPrefix string     `json:"tokenPrefix"`
	Enabled     bool       `json:"enabled"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
	CreatedBy   string     `json:"createdBy"`
	LastUsedAt  *time.Time `json:"lastUsedAt,omitempty"`

	// HMAC verification config. All optional; absent fields disable HMAC.
	HMACSecret    string `json:"hmacSecret,omitempty"`
	HMACAlgorithm string `json:"hmacAlgorithm,omitempty"`
	HMACHeader    string `json:"hmacHeader,omitempty"`
	HMACPrefix    string `json:"hmacPrefix,omitempty"`
}

// ToStorage converts a Webhook to WebhookForStorage for persistence.
// NOTE: When adding new fields to Webhook or WebhookForStorage, ensure both
// ToStorage and ToWebhook are updated to maintain field synchronization.
func (w *Webhook) ToStorage() *WebhookForStorage {
	return &WebhookForStorage{
		ID:            w.ID,
		DAGName:       w.DAGName,
		TokenHash:     w.TokenHash,
		TokenPrefix:   w.TokenPrefix,
		Enabled:       w.Enabled,
		CreatedAt:     w.CreatedAt,
		UpdatedAt:     w.UpdatedAt,
		CreatedBy:     w.CreatedBy,
		LastUsedAt:    w.LastUsedAt,
		HMACSecret:    w.HMACSecret,
		HMACAlgorithm: w.HMACAlgorithm,
		HMACHeader:    w.HMACHeader,
		HMACPrefix:    w.HMACPrefix,
	}
}

// ToWebhook converts WebhookForStorage back to Webhook.
// NOTE: When adding new fields to Webhook or WebhookForStorage, ensure both
// ToStorage and ToWebhook are updated to maintain field synchronization.
func (s *WebhookForStorage) ToWebhook() *Webhook {
	return &Webhook{
		ID:            s.ID,
		DAGName:       s.DAGName,
		TokenHash:     s.TokenHash,
		TokenPrefix:   s.TokenPrefix,
		Enabled:       s.Enabled,
		CreatedAt:     s.CreatedAt,
		UpdatedAt:     s.UpdatedAt,
		CreatedBy:     s.CreatedBy,
		LastUsedAt:    s.LastUsedAt,
		HMACSecret:    s.HMACSecret,
		HMACAlgorithm: s.HMACAlgorithm,
		HMACHeader:    s.HMACHeader,
		HMACPrefix:    s.HMACPrefix,
	}
}
