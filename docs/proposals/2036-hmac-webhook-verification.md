# Design — Native HMAC-SHA256 verification on webhook deliveries

Tracking issue: [dagucloud/dagu#2036](https://github.com/dagucloud/dagu/issues/2036)

## 1. Problem statement

Today, Dagu webhook deliveries are authenticated by a per-DAG bearer token
(`dagu_wh_…`). The token proves the caller knows a shared URL secret, but it
does **not** authenticate the *body* of the request: anyone in possession of
the token can deliver any payload, and there is no way to verify that the
payload originated from a known sender.

Major webhook providers solve this by signing the request body with HMAC and
sending the digest in a header (GitHub `X-Hub-Signature-256`, Stripe
`Stripe-Signature`, Slack `X-Slack-Signature`, Gitea `X-Gitea-Signature`).
Issue #2036 asks for this to be supported natively in Dagu so DAGs do not have
to glue verification logic into their first step.

The rationale called out in the issue is **defense-in-depth**: a leaked Dagu
token and a leaked HMAC secret are independent surfaces — compromising both is
strictly harder than compromising one.

## 2. Goals / non-goals

### Goals

- Allow each webhook to carry an optional HMAC verification configuration:
  secret, signature header name, value prefix, algorithm.
- When configured, reject deliveries whose signature header is missing or
  does not match a constant-time comparison against the locally computed
  digest, **before** any DAG run is enqueued.
- Keep the existing bearer-token check unchanged. HMAC is layered *on top*.
- Configurable enough to cover the common providers out of the box
  (GitHub, Gitea, Stripe-style `t=…,v1=…` is **out of scope** for v1; see §7).

### Non-goals

- HMAC-only (token-less) verification, e.g. accepting GitHub's webhook
  unmodified without also setting the Dagu bearer token. The issue explicitly
  frames HMAC as defense-in-depth, so v1 keeps both required when both are
  configured. Token-less HMAC may be added later behind a flag.
- Header passthrough to the DAG step (covered by sibling issue #2037).
- Stripe's compound `Stripe-Signature` format (`t=…,v1=…`) — same v2 follow-up.
- Encryption-at-rest for the secret; we already store the bcrypt hash of the
  bearer token next to it, and the data dir is `0600`. Documented as a
  known limitation; see §6.

## 3. User-visible surface

### 3.1 Webhook configuration model

A webhook gains four optional fields:

| Field            | Type    | Default                  | Notes |
|------------------|---------|--------------------------|-------|
| `hmacSecret`     | string  | unset                    | Stored as plaintext (it is a symmetric key — we cannot hash it). Never returned by the API. |
| `hmacAlgorithm`  | enum    | `sha256`                 | Only `sha256` for v1. Reserved for future `sha1`/`sha512`. |
| `hmacHeader`     | string  | `X-Hub-Signature-256`    | Header to read the signature from (case-insensitive). |
| `hmacPrefix`     | string  | `sha256=`                | Prefix to strip from the header value before hex-decoding. Empty string means no prefix. |

When `hmacSecret` is unset, no HMAC verification is performed (existing
behavior).

### 3.2 OpenAPI

- New schema `WebhookHMACConfig`: `{ algorithm, header, prefix }`. The
  secret is **write-only** and only present in request bodies / never
  returned in responses.
- `WebhookDetails`: gain `hmacEnabled: bool` and `hmac?: WebhookHMACConfig`
  (without secret) so the UI can show "HMAC: enabled, header=X-…".
- `CreateDAGWebhookRequest` (new request body): optional `hmac` block with
  `secret` + the three config fields.
- `RegenerateDAGWebhookTokenRequest`: unchanged. HMAC is not re-rotated when
  the bearer token is rotated; that is a separate operation.
- New endpoints (mirroring the existing `/regenerate` and `/toggle` patterns):
  - `PUT /dags/{fileName}/webhook/hmac` — set or replace the HMAC config.
    Body includes `secret` and optional config overrides. Idempotent.
  - `DELETE /dags/{fileName}/webhook/hmac` — clear the HMAC config (returns
    the webhook to bearer-only auth).

### 3.3 Trigger endpoint behavior

The flow at `POST /api/v1/webhooks/{fileName}` becomes:

1. Existing: extract & bcrypt-validate bearer token.
2. Existing: load DAG, capture raw body via middleware.
3. **New**: if `webhook.HMACSecret != ""`:
   1. Read the configured header from the request (default `X-Hub-Signature-256`).
   2. If missing → `401 Unauthorized` with `auth.token_invalid`.
   3. Strip the configured prefix (default `sha256=`).
   4. Hex-decode the remainder. If that fails → `401`.
   5. Compute `HMAC-SHA256(rawBody, secret)`.
   6. `hmac.Equal(expected, provided)` → on mismatch, `401`.
4. Existing: marshal payload param, idempotency check, enqueue.

All HMAC failure modes return `401` with a generic message — we do not leak
which check failed (matches how the bearer path works today).

## 4. Implementation plan

### 4.1 Domain types — `internal/auth/webhook.go`

Extend `Webhook` and `WebhookForStorage` symmetrically with the four fields,
update `ToStorage` / `ToWebhook`. Keep `HMACSecret` excluded from the
`json:"-"` Webhook view (same trick as `TokenHash`) so accidental logging /
API-response marshaling can't leak it.

### 4.2 Persistence — `internal/persis/filewebhook/store.go`

No interface changes; the storage struct is already JSON-marshaled to disk
behind `0600` files. Adding fields is automatically picked up. Existing
files without the new keys round-trip fine because Go's JSON decoder leaves
unknown fields zero-valued and the new fields are all optional.

### 4.3 Service — `internal/service/auth/service.go`

- Add `SetWebhookHMAC(ctx, dagName, cfg HMACConfig) (*auth.Webhook, error)`
  and `ClearWebhookHMAC(ctx, dagName) (*auth.Webhook, error)`.
- Validation (in service layer):
  - `secret` must be 16–4096 bytes (lower bound prevents trivial/empty
    keys; upper bound is a sanity guard).
  - `algorithm` must be `""` (defaults to `sha256`) or `sha256`.
  - `header` must match `^[A-Za-z0-9-]+$` and be ≤128 chars.
  - `prefix` ≤32 chars.
- On `CreateWebhook`, accept an optional `*HMACConfig` so the caller can
  set HMAC and bearer in one shot (simpler UX — and the audit log gets one
  entry instead of two).

### 4.4 HMAC verification — `internal/auth/webhook_hmac.go` (new)

Pure function:

```go
func VerifyHMAC(w *Webhook, header http.Header, body []byte) error
```

- Returns `nil` if not configured (so the trigger handler can call it
  unconditionally).
- Returns `ErrInvalidWebhookSignature` for missing header, bad prefix,
  bad hex, or digest mismatch.
- Uses `hmac.Equal` for constant-time comparison.

Living in `internal/auth/` (not in the API package) keeps it independently
unit-testable and reusable if a non-HTTP transport ever shows up.

### 4.5 Trigger handler — `internal/service/frontend/api/v1/webhooks.go`

Inside `TriggerWebhook`, after successful bearer validation and before
`marshalWebhookPayload`, call `auth.VerifyHMAC(webhook, http.Header(...), rawBody)`.

The handler currently only sees `request.Params.Authorization` — it does not
have the `*http.Request` directly. Two options:

1. Plumb additional headers (specifically the configured one) through the
   generated request struct via OpenAPI parameter declarations. Brittle —
   the header name is dynamic.
2. **Chosen**: capture `r.Header` in the existing
   `WebhookRawBodyMiddleware` (we already capture `r.Body`), stash it in
   the same context under a sibling key. The handler reads it via a new
   `webhookHeadersFromContext(ctx)`.

Option 2 is consistent with how raw body is already plumbed and avoids
churn in the OpenAPI spec for a feature that needs arbitrary headers.

### 4.6 Audit logging

Add audit categories: `webhook_hmac_set`, `webhook_hmac_clear`. Do **not**
log the secret value, only `hmacEnabled=true/false`, header name, and the
webhook ID. Matches the existing webhook audit pattern.

### 4.7 Frontend (`ui/`)

Out of scope for this PR — the issue is about server-side native support.
The OpenAPI types regenerate automatically and the UI keeps working without
HMAC. A follow-up PR can surface the new fields in the webhook management
UI. Documented in the PR description.

## 5. Tests

### 5.1 Unit — HMAC verifier

`internal/auth/webhook_hmac_test.go` exercises:

- No HMAC configured → `nil` regardless of headers/body.
- Valid signature with default header/prefix → `nil`.
- Custom header (`X-Gitea-Signature`) and empty prefix → `nil`.
- Missing header → `ErrInvalidWebhookSignature`.
- Wrong prefix on header value → `ErrInvalidWebhookSignature`.
- Non-hex digest → `ErrInvalidWebhookSignature`.
- Correct length, wrong digest → `ErrInvalidWebhookSignature`.
- Body tampering → `ErrInvalidWebhookSignature` (regression case).

### 5.2 Service

`internal/service/auth/webhook_test.go`: cases for `SetWebhookHMAC` /
`ClearWebhookHMAC` including validation errors and "webhook not found".

### 5.3 API integration

Extend `internal/service/frontend/api/v1/webhooks_test.go`:

- `TestWebhooks_TriggerWithValidHMAC` — secret configured, valid signature
  → 200, run enqueued.
- `TestWebhooks_TriggerWithInvalidHMAC` → 401, no run.
- `TestWebhooks_TriggerMissingHMACHeader` → 401, no run.
- `TestWebhooks_TriggerHMACWithCustomHeaderAndEmptyPrefix` (Gitea-style).
- `TestWebhooks_HMACCRUD` — set, list (config visible, secret not), clear.
- `TestWebhooks_TriggerHMACDoesNotConsumeBody` — payload still reaches the
  DAG correctly when HMAC verification passes.

### 5.4 Existing tests

Run `make test` and `make lint`. Everything else should be unaffected.

## 6. Security considerations

- **Storage of the secret.** The HMAC secret is stored plaintext on disk.
  This is intentional — HMAC requires the symmetric key at verification
  time. The webhooks directory uses `0600` files, same as other secrets in
  Dagu. A future hardening PR could integrate with the existing secret
  manager in `internal/cmn/secret/`.
- **Constant-time comparison.** `hmac.Equal` (timing-safe) is used. Hex
  decoding of the supplied digest happens *before* the comparison so we
  compare bytes, not strings of varying length.
- **Body capture.** We already capture the body up to 1MB
  (`maxWebhookPayloadSize`) for payload marshaling. The same captured
  bytes are used for HMAC verification — we never recompute the body from
  the parsed JSON, which would change byte representation and break
  signatures.
- **No secret in logs/metrics/audit.** `Webhook.HMACSecret` is tagged
  `json:"-"`. Audit entries only contain header name and `enabled`.
- **Config-validation regex** on `hmacHeader` prevents header injection
  through the configuration channel.

## 7. Compatibility & migration

- Existing webhook files on disk decode unchanged; new fields default to
  zero, which means HMAC is not enforced. No migration script needed.
- Existing API clients keep working: `WebhookDetails` only *gains*
  optional fields.
- DAGs whose first step today does its own HMAC verification keep working;
  they can drop that logic at their own pace once they enable
  server-side HMAC.

## 8. Out-of-scope follow-ups

1. Native UI for managing HMAC config.
2. Token-less HMAC mode for accepting GitHub/Gitea/Stripe webhooks
   directly (gated behind an explicit "external provider" mode).
3. Stripe-style compound signature parsing (`t=…,v1=…`).
4. Header passthrough to the DAG (issue #2037).
5. Encrypting the HMAC secret at rest using `internal/cmn/secret/`.

## 9. Open questions for review

- **Q1.** Should the default header be `X-Hub-Signature-256` (GitHub) or
  something Dagu-specific like `X-Dagu-Signature-256`? Recommendation:
  GitHub default — matches the most common ecosystem and we expect users
  to override it for other providers.
- **Q2.** Should `CreateDAGWebhook` accept HMAC config in the same call,
  or require a separate `PUT …/hmac`? Recommendation: accept on create
  (one audit entry, simpler client UX) **and** keep the dedicated
  endpoints for later updates.
- **Q3.** Minimum secret length — proposing 16 bytes. Reject shorter to
  avoid accidentally weak secrets, but allow up to 4096 to support keys
  pasted in any reasonable format.
