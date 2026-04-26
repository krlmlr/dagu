// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/dagucloud/dagu/api/v1"
	"github.com/dagucloud/dagu/internal/auth"
	"github.com/dagucloud/dagu/internal/cmn/logger"
	"github.com/dagucloud/dagu/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/internal/service/audit"
	authservice "github.com/dagucloud/dagu/internal/service/auth"
)

// SetDAGWebhookHMAC sets or replaces the HMAC verification configuration for
// a DAG's webhook. The secret is required; algorithm/header/prefix fall back
// to platform defaults when omitted.
//
// Validation errors yield 400; missing webhook yields 404. The response body
// returns updated WebhookDetails with hmacEnabled=true (the secret is never
// returned).
func (a *API) SetDAGWebhookHMAC(ctx context.Context, request api.SetDAGWebhookHMACRequestObject) (api.SetDAGWebhookHMACResponseObject, error) {
	if err := a.requireWebhookManagement(ctx); err != nil {
		return nil, err
	}

	if request.Body == nil {
		return nil, &Error{
			HTTPStatus: http.StatusBadRequest,
			Code:       api.ErrorCodeBadRequest,
			Message:    "request body is required",
		}
	}

	// Resolve defaults at configuration time so the persisted record is
	// self-describing. Otherwise an explicitly-empty prefix (Gitea-style)
	// would be indistinguishable from "use the platform default".
	cfg := authservice.HMACConfig{
		Secret:    request.Body.Secret,
		Algorithm: auth.DefaultHMACAlgorithm,
		Header:    auth.DefaultHMACHeader,
		Prefix:    auth.DefaultHMACPrefix,
	}
	if request.Body.Algorithm != nil && *request.Body.Algorithm != "" {
		cfg.Algorithm = string(*request.Body.Algorithm)
	}
	if request.Body.Header != nil && *request.Body.Header != "" {
		cfg.Header = *request.Body.Header
	}
	if request.Body.Prefix != nil {
		// Pointer present (even with empty string) → caller is explicit.
		cfg.Prefix = *request.Body.Prefix
	}

	webhook, err := a.authService.SetWebhookHMAC(ctx, request.FileName, cfg)
	if err != nil {
		switch {
		case errors.Is(err, authservice.ErrInvalidHMACSecret),
			errors.Is(err, authservice.ErrInvalidHMACAlgorithm),
			errors.Is(err, authservice.ErrInvalidHMACHeader),
			errors.Is(err, authservice.ErrInvalidHMACPrefix):
			return nil, &Error{
				HTTPStatus: http.StatusBadRequest,
				Code:       api.ErrorCodeBadRequest,
				Message:    err.Error(),
			}
		case errors.Is(err, auth.ErrWebhookNotFound):
			return nil, &Error{
				HTTPStatus: http.StatusNotFound,
				Code:       api.ErrorCodeNotFound,
				Message:    fmt.Sprintf("no webhook configured for DAG %s", request.FileName),
			}
		}
		logger.Error(ctx, "Failed to set webhook HMAC", tag.Name(request.FileName), tag.Error(err))
		return nil, &Error{
			HTTPStatus: http.StatusInternalServerError,
			Code:       api.ErrorCodeInternalError,
			Message:    "failed to set webhook HMAC",
		}
	}

	logger.Info(ctx, "Webhook HMAC set", tag.Name(request.FileName))
	a.logAudit(ctx, audit.CategoryWebhook, "webhook_hmac_set", map[string]any{
		"dag_name":   request.FileName,
		"webhook_id": webhook.ID,
		"header":     webhook.HMACHeaderOrDefault(),
		"algorithm":  webhook.HMACAlgorithmOrDefault(),
	})

	return api.SetDAGWebhookHMAC200JSONResponse(toWebhookDetails(webhook)), nil
}

// ClearDAGWebhookHMAC removes the HMAC verification configuration from the
// webhook. Subsequent deliveries are authenticated by the bearer token alone.
func (a *API) ClearDAGWebhookHMAC(ctx context.Context, request api.ClearDAGWebhookHMACRequestObject) (api.ClearDAGWebhookHMACResponseObject, error) {
	if err := a.requireWebhookManagement(ctx); err != nil {
		return nil, err
	}

	webhook, err := a.authService.ClearWebhookHMAC(ctx, request.FileName)
	if err != nil {
		if errors.Is(err, auth.ErrWebhookNotFound) {
			return nil, &Error{
				HTTPStatus: http.StatusNotFound,
				Code:       api.ErrorCodeNotFound,
				Message:    fmt.Sprintf("no webhook configured for DAG %s", request.FileName),
			}
		}
		logger.Error(ctx, "Failed to clear webhook HMAC", tag.Name(request.FileName), tag.Error(err))
		return nil, &Error{
			HTTPStatus: http.StatusInternalServerError,
			Code:       api.ErrorCodeInternalError,
			Message:    "failed to clear webhook HMAC",
		}
	}

	logger.Info(ctx, "Webhook HMAC cleared", tag.Name(request.FileName))
	a.logAudit(ctx, audit.CategoryWebhook, "webhook_hmac_clear", map[string]any{
		"dag_name":   request.FileName,
		"webhook_id": webhook.ID,
	})

	return api.ClearDAGWebhookHMAC200JSONResponse(toWebhookDetails(webhook)), nil
}
