// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/dagucloud/dagu/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// computeHMACHex returns hex(HMAC-SHA256(body, secret)) — the digest format
// used by GitHub-style providers.
func computeHMACHex(t *testing.T, secret string, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	_, err := mac.Write(body)
	require.NoError(t, err)
	return hex.EncodeToString(mac.Sum(nil))
}

// TestWebhooks_HMACManagementCRUD covers the new management endpoints and
// confirms that the secret is never returned in API responses.
func TestWebhooks_HMACManagementCRUD(t *testing.T) {
	t.Parallel()

	dagName := "webhook_hmac_crud"
	server := setupWebhookTestServer(t)
	adminToken := getWebhookAdminToken(t, server)
	createTestDAG(t, server, adminToken, dagName)
	server.Client().Post("/api/v1/dags/"+dagName+"/webhook", nil).
		WithBearerToken(adminToken).
		ExpectStatus(http.StatusCreated).Send(t)

	// 1) Set HMAC config.
	setBody := api.WebhookHMACSetRequest{
		Secret: "0123456789abcdef-secret",
	}
	resp := server.Client().Put("/api/v1/dags/"+dagName+"/webhook/hmac", setBody).
		WithBearerToken(adminToken).
		ExpectStatus(http.StatusOK).Send(t)

	var details api.WebhookDetails
	resp.Unmarshal(t, &details)
	assert.True(t, details.HmacEnabled)
	require.NotNil(t, details.Hmac)
	assert.Equal(t, "sha256", details.Hmac.Algorithm)
	assert.Equal(t, "X-Hub-Signature-256", details.Hmac.Header)
	assert.Equal(t, "sha256=", details.Hmac.Prefix)
	// Secret must never appear in the JSON response body.
	assert.NotContains(t, resp.Body, "0123456789abcdef-secret")
	assert.NotContains(t, resp.Body, "hmacSecret")

	// 2) GET also reflects HMAC config without secret.
	getResp := server.Client().Get("/api/v1/dags/" + dagName + "/webhook").
		WithBearerToken(adminToken).
		ExpectStatus(http.StatusOK).Send(t)
	var got api.WebhookDetails
	getResp.Unmarshal(t, &got)
	assert.True(t, got.HmacEnabled)
	require.NotNil(t, got.Hmac)
	assert.Equal(t, "X-Hub-Signature-256", got.Hmac.Header)

	// 3) Replace with custom config.
	customAlg := api.WebhookHMACSetRequestAlgorithmSha256
	customHeader := "X-Gitea-Signature"
	customPrefix := ""
	server.Client().Put("/api/v1/dags/"+dagName+"/webhook/hmac", api.WebhookHMACSetRequest{
		Secret:    "rotated-secret-1234567",
		Algorithm: &customAlg,
		Header:    &customHeader,
		Prefix:    &customPrefix,
	}).WithBearerToken(adminToken).ExpectStatus(http.StatusOK).Send(t)

	getResp = server.Client().Get("/api/v1/dags/" + dagName + "/webhook").
		WithBearerToken(adminToken).
		ExpectStatus(http.StatusOK).Send(t)
	getResp.Unmarshal(t, &got)
	require.NotNil(t, got.Hmac)
	assert.Equal(t, "X-Gitea-Signature", got.Hmac.Header)

	// 4) Clear HMAC config.
	clearResp := server.Client().Delete("/api/v1/dags/" + dagName + "/webhook/hmac").
		WithBearerToken(adminToken).
		ExpectStatus(http.StatusOK).Send(t)
	var cleared api.WebhookDetails
	clearResp.Unmarshal(t, &cleared)
	assert.False(t, cleared.HmacEnabled)
	assert.Nil(t, cleared.Hmac)
}

func TestWebhooks_HMACSet_RejectsShortSecret(t *testing.T) {
	t.Parallel()
	dagName := "webhook_hmac_short_secret"
	server := setupWebhookTestServer(t)
	adminToken := getWebhookAdminToken(t, server)
	createTestDAG(t, server, adminToken, dagName)
	server.Client().Post("/api/v1/dags/"+dagName+"/webhook", nil).
		WithBearerToken(adminToken).ExpectStatus(http.StatusCreated).Send(t)

	server.Client().Put("/api/v1/dags/"+dagName+"/webhook/hmac",
		api.WebhookHMACSetRequest{Secret: "tooshort"}).
		WithBearerToken(adminToken).
		ExpectStatus(http.StatusBadRequest).Send(t)
}

func TestWebhooks_HMACSet_NoWebhookYields404(t *testing.T) {
	t.Parallel()
	dagName := "webhook_hmac_no_webhook"
	server := setupWebhookTestServer(t)
	adminToken := getWebhookAdminToken(t, server)
	createTestDAG(t, server, adminToken, dagName)

	server.Client().Put("/api/v1/dags/"+dagName+"/webhook/hmac",
		api.WebhookHMACSetRequest{Secret: "0123456789abcdef-secret"}).
		WithBearerToken(adminToken).
		ExpectStatus(http.StatusNotFound).Send(t)

	server.Client().Delete("/api/v1/dags/" + dagName + "/webhook/hmac").
		WithBearerToken(adminToken).
		ExpectStatus(http.StatusNotFound).Send(t)
}

// TestWebhooks_TriggerHMAC exercises the trigger endpoint with HMAC configured.
// We marshal the request body ourselves (and pre-compute the signature over
// the exact bytes the server will receive), avoiding any non-determinism in
// the test client's encoder.
func TestWebhooks_TriggerHMAC(t *testing.T) {
	t.Parallel()
	dagName := "webhook_hmac_trigger"
	server := setupWebhookTestServer(t)
	adminToken := getWebhookAdminToken(t, server)
	createTestDAG(t, server, adminToken, dagName)

	createResp := server.Client().Post("/api/v1/dags/"+dagName+"/webhook", nil).
		WithBearerToken(adminToken).ExpectStatus(http.StatusCreated).Send(t)
	var created api.WebhookCreateResponse
	createResp.Unmarshal(t, &created)
	webhookToken := created.Token

	// Configure HMAC with default header/prefix.
	secret := "0123456789abcdef-secret"
	server.Client().Put("/api/v1/dags/"+dagName+"/webhook/hmac",
		api.WebhookHMACSetRequest{Secret: secret}).
		WithBearerToken(adminToken).ExpectStatus(http.StatusOK).Send(t)

	// Build the body bytes.
	payload := map[string]any{"event": "push", "ref": "main"}
	bodyBytes, err := json.Marshal(api.WebhookRequest{Payload: &payload})
	require.NoError(t, err)

	t.Run("ValidSignature_DefaultHeader", func(t *testing.T) {
		t.Parallel()
		sig := "sha256=" + computeHMACHex(t, secret, bodyBytes)
		// Use json.RawMessage so the test client sends bodyBytes verbatim.
		server.Client().Post("/api/v1/webhooks/"+dagName, json.RawMessage(bodyBytes)).
			WithBearerToken(webhookToken).
			WithHeader("X-Hub-Signature-256", sig).
			ExpectStatus(http.StatusOK).Send(t)
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		t.Parallel()
		server.Client().Post("/api/v1/webhooks/"+dagName, json.RawMessage(bodyBytes)).
			WithBearerToken(webhookToken).
			WithHeader("X-Hub-Signature-256", "sha256=deadbeef").
			ExpectStatus(http.StatusUnauthorized).Send(t)
	})

	t.Run("MissingSignatureHeader", func(t *testing.T) {
		t.Parallel()
		server.Client().Post("/api/v1/webhooks/"+dagName, json.RawMessage(bodyBytes)).
			WithBearerToken(webhookToken).
			ExpectStatus(http.StatusUnauthorized).Send(t)
	})

	t.Run("BodyTamperedAfterSigning", func(t *testing.T) {
		t.Parallel()
		// Sign one body, send a different one.
		sig := "sha256=" + computeHMACHex(t, secret, bodyBytes)
		other := []byte(`{"payload":{"event":"push","ref":"prod"}}`)
		server.Client().Post("/api/v1/webhooks/"+dagName, json.RawMessage(other)).
			WithBearerToken(webhookToken).
			WithHeader("X-Hub-Signature-256", sig).
			ExpectStatus(http.StatusUnauthorized).Send(t)
	})
}

// TestWebhooks_TriggerHMAC_GiteaStyle pins the empty-prefix configuration
// which is what Gitea sends on X-Gitea-Signature.
func TestWebhooks_TriggerHMAC_GiteaStyle(t *testing.T) {
	t.Parallel()
	dagName := "webhook_hmac_gitea"
	server := setupWebhookTestServer(t)
	adminToken := getWebhookAdminToken(t, server)
	createTestDAG(t, server, adminToken, dagName)

	createResp := server.Client().Post("/api/v1/dags/"+dagName+"/webhook", nil).
		WithBearerToken(adminToken).ExpectStatus(http.StatusCreated).Send(t)
	var created api.WebhookCreateResponse
	createResp.Unmarshal(t, &created)
	webhookToken := created.Token

	secret := "gitea-shared-secret-1"
	header := "X-Gitea-Signature"
	emptyPrefix := ""
	alg := api.WebhookHMACSetRequestAlgorithmSha256
	server.Client().Put("/api/v1/dags/"+dagName+"/webhook/hmac",
		api.WebhookHMACSetRequest{
			Secret:    secret,
			Algorithm: &alg,
			Header:    &header,
			Prefix:    &emptyPrefix,
		}).
		WithBearerToken(adminToken).ExpectStatus(http.StatusOK).Send(t)

	payload := map[string]any{"action": "push"}
	bodyBytes, err := json.Marshal(api.WebhookRequest{Payload: &payload})
	require.NoError(t, err)
	sig := computeHMACHex(t, secret, bodyBytes)

	server.Client().Post("/api/v1/webhooks/"+dagName, json.RawMessage(bodyBytes)).
		WithBearerToken(webhookToken).
		WithHeader("X-Gitea-Signature", sig).
		ExpectStatus(http.StatusOK).Send(t)

	// Sending the GitHub-style sha256= prefix on the same header should now fail.
	server.Client().Post("/api/v1/webhooks/"+dagName, json.RawMessage(bodyBytes)).
		WithBearerToken(webhookToken).
		WithHeader("X-Gitea-Signature", "sha256="+sig).
		ExpectStatus(http.StatusUnauthorized).Send(t)
}

// TestWebhooks_TriggerHMAC_BearerStillRequired confirms defense-in-depth:
// even with a valid HMAC signature, a missing bearer token returns 401.
func TestWebhooks_TriggerHMAC_BearerStillRequired(t *testing.T) {
	t.Parallel()
	dagName := "webhook_hmac_bearer_required"
	server := setupWebhookTestServer(t)
	adminToken := getWebhookAdminToken(t, server)
	createTestDAG(t, server, adminToken, dagName)
	server.Client().Post("/api/v1/dags/"+dagName+"/webhook", nil).
		WithBearerToken(adminToken).ExpectStatus(http.StatusCreated).Send(t)

	secret := "0123456789abcdef-secret"
	server.Client().Put("/api/v1/dags/"+dagName+"/webhook/hmac",
		api.WebhookHMACSetRequest{Secret: secret}).
		WithBearerToken(adminToken).ExpectStatus(http.StatusOK).Send(t)

	bodyBytes, err := json.Marshal(api.WebhookRequest{})
	require.NoError(t, err)
	sig := "sha256=" + computeHMACHex(t, secret, bodyBytes)

	// No Authorization header at all → 401.
	server.Client().Post("/api/v1/webhooks/"+dagName, json.RawMessage(bodyBytes)).
		WithHeader("X-Hub-Signature-256", sig).
		ExpectStatus(http.StatusUnauthorized).Send(t)
}
