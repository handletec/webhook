## Golang Webhook Library

This library provides outbound webhook delivery for Go applications: `POST`,
`PUT`, `PATCH`, `GET`, `DELETE`, with per-hook authentication (`none`,
`basic`, `bearer`, `token`), YAML/JSON configuration, opt-in retry, and
context-aware cancellation/timeouts.

`POST`/`PUT`/`PATCH` send a JSON body. `GET`/`DELETE` send no HTTP body;
any data you provide is flattened into the query string instead.

Delivery status is checked: a response outside the configured success
range (2xx by default) is returned as a `*DeliveryError`, not silently
ignored.

Webhook redirects are not followed. Configure each webhook with its final
destination URL -- see [Security and Operational Considerations](#security-and-operational-considerations)
for details.

## Quick start (HTTP POST with JSON body)

```go
package main

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"time"

	"github.com/handletec/webhook"
)

type WebHookRequest struct {
	Action    string `json:"action"`
	Timestamp string `json:"timestamp"`
}

func main() {
	// Payload (raw JSON bytes)
	body, err := json.Marshal(&WebHookRequest{
		Action:    "create",
		Timestamp: time.Now().Format(time.RFC3339),
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create registry and add an endpoint (no auth)
	whs := webhook.NewWebHooks()
	if err := whs.Add(webhook.MethodPost, "https://api.example.com/webhook", webhook.WithNoAuth()); err != nil {
		log.Fatal(err)
	}

	// TLS for testing only; do NOT use InsecureSkipVerify in production
	tlsCfg := &tls.Config{InsecureSkipVerify: true}

	// Optional headers
	h := webhook.NewHeaders()
	h.SetUserAgent("my-agent/v1-post")


	// Send to all registered hooks
	if err := whs.Broadcast(tlsCfg, webhook.WithData(body), webhook.WithHeaders(h)); err != nil {
		log.Fatal(err)
	}
}
```

You can also let the library marshal for you:

```go
_ = whs.Broadcast(tlsCfg, webhook.WithJSON(WebHookRequest{Action: "create", Timestamp: time.Now().Format(time.RFC3339)}))
```

---

## Context, cancellation, and timeouts

Every send has a `*Context` form that takes a `context.Context` for
cancellation/deadlines; the non-`Context` form is a thin wrapper over
`context.Background()`:

```go
(wh *WebHook) Send(tlsConfig, body, query, headers) error
(wh *WebHook) SendContext(ctx, tlsConfig, body, query, headers) error

(whs WebHooks) Send(method, tlsCfg, opts...) error
(whs WebHooks) SendContext(ctx, method, tlsCfg, opts...) error

(whs WebHooks) Broadcast(tlsCfg, opts...) error
(whs WebHooks) BroadcastContext(ctx, tlsCfg, opts...) error
```

Use the `*Context` forms whenever you have a request-scoped context to
propagate (e.g. an incoming HTTP handler's context) so a slow or hung
endpoint can be cancelled along with the rest of the request, and so
`errors.Is(err, context.Canceled)` / `errors.Is(err, context.DeadlineExceeded)`
work through the returned error.

Each hook has its own timeout, 15s by default, overridable per hook:

```go
wh, err := webhook.NewWebHook(webhook.MethodPost, addr,
	webhook.WithTimeout(5*time.Second),
)
```

---

## Authentication

### Basic

`Authorization: Basic <base64(username:password)>`

```go
whs := webhook.NewWebHooks()
_ = whs.Add(webhook.MethodPost, "https://api.example.com/webhook",
    webhook.WithBasicAuth("hello", "world"),
)
```

### Bearer

`Authorization: Bearer <token>`

```go
whs := webhook.NewWebHooks()
_ = whs.Add(webhook.MethodPost, "https://api.example.com/webhook",
    webhook.WithBearerToken("mysupersecrettoken"),
)
```

### Token (custom header)

`X-Api-Key: <value>` (or any header name you choose)

```go
whs := webhook.NewWebHooks()
_ = whs.Add(webhook.MethodPost, "https://api.example.com/webhook",
    webhook.WithToken("X-Api-Key", "secret"),
)
```

`NewWebHook`'s `With*Auth` options *are* the secret-setting mechanism, so
the secret is required immediately -- construction fails if it's missing.

### Deferred binding via `ApplyAuth` (recommended for config-loaded hooks)

Config files (YAML/JSON) only ever need to declare `authType` (+ a header
name for `token`) -- **no secret needs to be in the file for any auth
type.** The real secret is bound later, typically from environment
variables or a secret manager, via `ApplyAuth`:

```go
err := whs.ApplyAuth(func(h *webhook.WebHook) error {
    switch h.AuthType {
    case webhook.AuthTypeBasic:
        user, pass := lookupBasic(h.Address)
        h.SetBasicAuth(user, pass)
    case webhook.AuthTypeBearer:
        h.SetBearerToken(lookupBearer(h.Address))
    case webhook.AuthTypeToken:
        h.SetCustomToken(h.AuthHeaderName, lookupToken(h.Address))
    case webhook.AuthTypeNone:
        // nothing to bind
    }
    return nil
})
```

`ApplyAuth` runs your binder, then validates every hook has a compiled
credential for its declared `AuthType` and returns an aggregated error for
any hook that doesn't (see "validity vs. readiness" below).

### Config validity vs. delivery readiness

These are two deliberately separate checks:

- **`validateAuthConfig`** (structural, parse time): is `AuthType` a known
  value, and for `token`, is a header name declared? Runs when YAML/JSON is
  parsed (`UnmarshalYAML`/`UnmarshalJSON`) and in `NewWebHook`. It does
  **not** require a secret -- a config that declares `authType: bearer`
  with no token parses cleanly.
- **`authReady`** (delivery readiness, send time): is the actual compiled
  secret present for the declared `AuthType`? Checked by `SendContext`
  before any network I/O (**fail closed**: a hook with a declared but
  unbound auth type never sends unauthenticated -- it returns a
  `*DeliveryError` instead) and by `ApplyAuth` after your binder runs.

### Fail-closed auth

If `AuthType != none` and the compiled credential is empty at send time,
`SendContext` refuses to send and returns a `*DeliveryError` for that hook.
It will never silently fall back to an unauthenticated request.

---

## Headers

```go
hdrs := webhook.NewHeaders()
hdrs.SetUserAgent("my-agent/v1")
hdrs.Set("X-Trace-Id", "12345")
hdrs.Add("X-Multi", "a")
hdrs.Add("X-Multi", "b")

if v, ok := hdrs.Get("X-Trace-Id"); ok {
    fmt.Println("trace:", v)
}
hdrs.Del("X-Multi")
```

Headers are cloned per request. Per-hook auth always wins over a
caller-supplied header of the same name, and a caller-supplied
`Authorization` header never reaches a hook whose own auth isn't
Basic/Bearer. Header names and values are validated (RFC 7230 token names,
no CR/LF in values) immediately before dispatch.

You can set persistent per-hook headers with `wh.SetHeader(name, value)` --
merged into every send for that hook, overridable per call via
`WithHeaders`.

---

## GET and DELETE

`GET` and `DELETE` use the **query string**. If you also supply data via `WithData`/`WithJSON`, it will be **flattened into query parameters** (best effort: primitives → `k=v`, arrays → repeated keys, nested objects → JSON string, `null` → skipped). Invalid JSON in this position now returns an error (previously it was silently dropped).

Precedence when the same key appears in more than one place: the
address's own query string, then `WithQuery`, then JSON-flattened fields
-- each stage can overwrite the previous one, and the effective value is
whatever the last stage set.

```go
whs := webhook.NewWebHooks()
_ = whs.Add(webhook.MethodGet, "https://api.example.com/webhook", webhook.WithNoAuth())

q := webhook.NewQuery()
q.Add("action", "create")
q.Add("timestamp", time.Now().Format(time.RFC3339))

tlsCfg := &tls.Config{InsecureSkipVerify: true} // testing only, see TLS section
hdrs := webhook.NewHeaders()
hdrs.SetUserAgent("my-agent/v1-get")

// You may provide both query AND data; data is merged into the query for GET/DELETE.
_ = whs.Broadcast(tlsCfg, webhook.WithQuery(q), webhook.WithJSON(map[string]any{"extra": "value"}), webhook.WithHeaders(hdrs))
```

---

## Success / failure semantics

A response is treated as a delivery failure unless its status code falls
in the configured success range -- **2xx by default**
(`httpclient.Response.IsSuccess()`), overridable per hook:

```go
wh, err := webhook.NewWebHook(webhook.MethodPost, addr,
	webhook.WithSuccessRange(200, 499), // e.g. treat 4xx as delivered, not a failure
)
```

An out-of-range status, or a transport-level failure (DNS, connection
refused, TLS handshake failure, timeout, context cancellation), is
returned as a `*DeliveryError`:

```go
type DeliveryError struct {
	Target     string // redacted: scheme://host[:port] -- never path or query
	Method     Method
	StatusCode int  // 0 for transport-level failures
	Retryable  bool // diagnostic hint only; does not affect dispatch
	Err        error
}
```

`Target` is redacted to `scheme://host[:port]` -- it never includes the
path or query string, since secrets (tokens, signed URLs) can appear in
either. `Unwrap()` exposes the underlying cause, so
`errors.Is(err, context.Canceled)` etc. still work.

---

## Retry (opt-in, off by default)

```go
wh, err := webhook.NewWebHook(webhook.MethodGet, addr,
	webhook.WithRetry(webhook.RetryPolicy{
		MaxAttempts: 3,
		BaseDelay:   200 * time.Millisecond,
		MaxDelay:    5 * time.Second,
		Multiplier:  2,
		Jitter:      true,
		// RetryOn defaults to [429, 500, 502, 503, 504] when nil.
	}),
)

// Or on an existing hook:
err = wh.SetRetry(webhook.RetryPolicy{MaxAttempts: 3})
```

**Exact scope -- read carefully, this is a dependency limitation, not a
design choice:**

- **Status-code based only.** Only responses whose status is in `RetryOn`
  (default `[429, 500, 502, 503, 504]`) are retried.
- **Network/transport errors are never retried.** Connection refused, DNS
  failure, TLS handshake failure, etc. always fail on the first attempt --
  confirmed by reading `github.com/svicknesh/httpclient`'s `connect()`,
  which returns immediately on a transport error without entering the
  retry loop.
- **`Retry-After` is not honored.** The dependency has no support for it.

**Non-idempotent guard:** `MaxAttempts > 1` on a hook whose method is
`POST`/`PATCH` requires `AllowNonIdempotentRetry: true`, or construction
fails with an error. `Method` stays an exported, directly-writable field
for compatibility, so it can be changed after `SetRetry` ran its own
check -- `SendContext` re-checks the guard against its own snapshot of
`(Method, RetryPolicy)` immediately before dispatch, so a hook can never
silently retry a non-idempotent request even via that sequence.

---

## Configuration (YAML / JSON)

YAML and JSON are now at genuine parity (previously JSON support was
entirely missing). Config only ever needs to declare `authType` -- never
the actual secret, for any auth type -- see "Deferred binding" above.

```yaml
# example.yaml
POST:
  - address: https://api.example.com/hookA          # shorthand item
  - address: https://api.example.com/hookB
    authType: bearer
    enabled: true
  - address: https://api.example.com/hookC
    authType: token
    authHeaderName: X-Api-Key
    enabled: true
GET:
  - address: https://api.example.com/audit
    authType: none
    enabled: true
```

Equivalent JSON:

```json
{
  "POST": [
    { "address": "https://api.example.com/hookA" },
    { "address": "https://api.example.com/hookB", "authType": "bearer", "enabled": true },
    { "address": "https://api.example.com/hookC", "authType": "token", "authHeaderName": "X-Api-Key", "enabled": true }
  ],
  "GET": [
    { "address": "https://api.example.com/audit", "authType": "none", "enabled": true }
  ]
}
```

```go
var whs webhook.WebHooks
if err := yaml.Unmarshal(data, &whs); err != nil { // or json.Unmarshal
	log.Fatal(err)
}
if err := whs.ApplyAuth(bindSecrets); err != nil {
	log.Fatal(err)
}
```

`WebHooks.MarshalJSON` always emits canonical method names (`"POST"`,
`"GET"`, ...) as map keys. `UnmarshalJSON` accepts both canonical names and
legacy raw-integer-string keys (e.g. `"2"`), for backward compatibility
with anything already serialized by an older, default `encoding/json`
map-key encoding (Go only consults a type's `MarshalJSON` for map
*values*, never map *keys*, unless the key type implements
`encoding.TextMarshaler`).

Marshaled output (both YAML and JSON) never includes `username`,
`password`, `token`, or any compiled secret value.

---

## Adding and removing hooks

```go
whs := webhook.NewWebHooks()

// Add (dedupes by address per method, case-insensitive)
_ = whs.Add(webhook.MethodPost, "https://api.example.com/hook", webhook.WithNoAuth())

// Remove
_ = whs.Remove(webhook.MethodPost, "https://api.example.com/hook")
```

`WebHooks` is a bare `map[Method][]*WebHook` -- iterate/index it directly
if you need to. It stays a bare map deliberately for compatibility with
existing consumers that do exactly that.

---

## Request options and rules

- `WithData([]byte)` — raw JSON body (POST/PUT/PATCH) or data to be merged into query (GET/DELETE). The slice is copied the moment `WithData` is called.
- `WithJSON(any)` — convenience: `json.Marshal` then treated like `WithData`.
- `WithQuery(webhook.Query)` — additional query params, cloned the moment `WithQuery` is called.
- `WithHeaders(webhook.Headers)` — extra headers, cloned the moment `WithHeaders` is called.
- `WithConcurrency(n int)` — override the default fan-out concurrency (`runtime.GOMAXPROCS(0)*4`).

Because `WithData`/`WithQuery`/`WithHeaders` copy their input immediately
(not deferred to send time), mutating your original slice/map *after*
calling them has no effect on what's actually sent -- `whs.Broadcast`
always sees an already-immutable, library-owned snapshot.

**Rules enforced by the library:**

- **POST/PUT/PATCH** require non-empty **data**.
- **GET/DELETE** never send an HTTP body; if **data** is supplied, it is **flattened into the query** (and invalid JSON now returns an error).
- When a body is sent (POST/PUT/PATCH), the library sets
  `Content-Type: application/json; charset=utf-8` and `Accept: application/json`.

---

## Concurrency and lifecycle

- `Send`/`Broadcast`/`SendContext`/`BroadcastContext` fan out concurrently
  using a bounded worker pool (`runtime.GOMAXPROCS(0)*4` by default,
  override with `WithConcurrency`).
- Errors from multiple targets are aggregated and returned (`errors.Join`).
- **Concurrent delivery together with the supported setter methods
  (`SetBasicAuth`, `SetBearerToken`, `SetCustomToken`, `SetHeader`,
  `SetRetry`) is safe.** `SendContext` takes a single, coherent snapshot of
  every piece of mutable per-hook state under one lock before doing any
  network I/O, so a concurrent setter call is never observed as a mix of
  old and new state.
- **Direct mutation of exported `WebHook` fields (`Enabled`, `Method`,
  `Address`, `AuthType`, `AuthHeaderName`) after concurrent delivery
  begins is unsupported** -- configure exported fields before starting
  concurrent delivery. These fields stay exported for compatibility with
  consumers that read/write them directly; Go has no way to intercept a
  plain field write, so this boundary cannot be enforced by the library,
  only documented.

---

## TLS

Pass a custom `*tls.Config` for mTLS or a custom CA:

```go
tlsCfg := &tls.Config{
	Certificates: []tls.Certificate{clientCert}, // mTLS
	RootCAs:      customCAPool,
}
_ = whs.Broadcast(tlsCfg, webhook.WithData(body))
```

Do not use `InsecureSkipVerify` outside of local tests against your own
ephemeral test servers.

---

## Security and Operational Considerations

### Redirects are not followed

Webhook redirects are not followed. Configure each webhook with its final
destination URL. HTTP `3xx` responses are treated as unsuccessful delivery
(a `*DeliveryError`) unless included in a custom success range via
`WithSuccessRange`.

Every delivery (`SendContext`/`Send`/`Broadcast`/`BroadcastContext`, for
every hook, regardless of `AuthType`) disables redirect-following on the
underlying `github.com/svicknesh/httpclient` request before dispatch. A
`3xx` response from the configured address is returned as an ordinary
response instead of being followed, so the redirect destination is never
contacted and no credential (`Authorization`, a custom `token`-auth header
such as `X-Api-Key`, etc.) is ever forwarded to it. This closes a
previously-documented gap in this library, where `httpclient` exposed no
`CheckRedirect` hook and Go's default `net/http` redirect policy could
forward credentials to a redirect target under some conditions (fixed by
`httpclient` v1.7.1's `DisableRedirects`, which this library now uses).

No manual redirect handling, `Location` inspection/retry, or origin/scheme
allowlisting is performed -- the configured `Address` is always the final
destination for every attempt, including retries (see below).

### Transport reuse

A fresh `httpclient.Request` (and therefore a fresh `*http.Transport` /
connection pool) is built on every `SendContext` call. This is a
dependency constraint, not a design choice: `httpclient.Request` is
confirmed unsafe to cache or share across calls or goroutines --
`SetHeader`/`SetBasicAuth`/`SetBearerToken` mutate a plain `http.Header`
map with no lock, and its jitter random source is explicitly documented as
not safe for concurrent use. `Request.Clone()` doesn't solve pool reuse
either -- it builds an independent transport with its own connection pool.
There is currently no way, with this dependency, to get both safe
concurrent/repeated use and a shared connection pool.

### Durable delivery

This library does not persist deliveries or retry forever. Its retry
support (see above) is a bounded, in-process, status-code-based backoff --
not a durable queue. If you need guaranteed eventual delivery across
process restarts, put an application-level outbox/queue in front of this
library.

---

## Migration notes (from pre-hardening versions)

- **Fail-closed auth:** a hook with a declared `AuthType` but no bound
  secret now returns a `*DeliveryError` instead of sending
  unauthenticated. If you relied on the old silent-unauthenticated
  fallback (e.g. a config-declared `bearer` hook that never had
  `SetBearerToken` called), delivery will now fail until you bind the
  secret via `ApplyAuth` or a `Set*` method.
- **Status is now checked.** Previously `Send` returned `nil` even for a
  non-2xx response ("fire and forget"). It now returns a `*DeliveryError`
  for out-of-range statuses; use `WithSuccessRange` if you need the old
  "don't care about status" behavior for a specific hook.
- **Stricter URL and header validation:** only `http`/`https` schemes are
  accepted, and embedded userinfo (`https://user:pass@host`) is rejected.
  Outbound headers are now validated immediately before dispatch (RFC 7230
  token names, no CR/LF in values); malformed input that older versions
  accepted may now be rejected.
- **Invalid JSON for GET/DELETE query-flattening now returns an error**
  instead of silently being dropped.
- **JSON marshal/unmarshal is now functional and secret-safe** for both
  `WebHook` and `WebHooks` (previously entirely missing on `WebHook`,
  which meant plaintext `username`/`password`/`token` fields were never
  compiled or wiped on the JSON path).
- **The URL-doubling bug is fixed:** hooks now receive the correct,
  undoubled path and query -- if you were compensating for the previous
  mangled URL on the receiving end, remove that workaround.
- `WebHooks` stays a bare `map[Method][]*WebHook`; `Send`/`Broadcast`
  keep their existing signatures. All new APIs (`SendContext`,
  `BroadcastContext`, `WithTimeout`, `WithSuccessRange`, `WithRetry`,
  `WithConcurrency`, `SetRetry`) are additive.
- **Redirects are no longer followed.** If a configured webhook address
  used to rely on a `3xx` redirect to reach its real destination, delivery
  will now fail (or succeed only if you widen the success range via
  `WithSuccessRange` to accept the `3xx` status) -- point the hook at the
  final URL directly instead.
