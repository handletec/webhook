## Golang Webhook Library

This library aims to provide an easy to use method for using webhooks in your applications. It provides webhook methods for 'POST', 'PUT', 'PATCH', 'GET', 'DELETE'

It supports using JSON body payloads for 'POST', 'PUT' and 'PATCH' and URL query parameters for 'GET' and 'DELETE'

You can set custom headers for webhooks and set authentication parameters suitable for authentication with remote endpoints. The supported authentication types are 'none', 'basic', 'bearer' and 'token'


### Summary

- **POST/PUT/PATCH** use **JSON body** (data is required).  
- **GET/DELETE** use **URL query parameters**. If you also provide **data**, it will be **flattened into query params** automatically (no HTTP body is sent for these verbs).
- You can attach custom headers and choose auth: **none**, **basic**, **bearer**, or **token**.
- **Security:** The library enforces per-hook auth: it **overwrites** any global `Authorization`/token headers for that hook and **removes** them when `authType` is `none`.


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
	if err := whs.Add(webhook.MethodPost, "https://echo.app.handletec.my", webhook.WithNoAuth()); err != nil {
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

## Authentication

### Basic

`Authorization: Basic <base64(username:password)>`

```go
whs := webhook.NewWebHooks()
_ = whs.Add(webhook.MethodPost, "https://echo.app.handletec.my",
    webhook.WithBasicAuth("hello", "world"),
)
```

### Bearer

`Authorization: Bearer <token>`

```go
whs := webhook.NewWebHooks()
_ = whs.Add(webhook.MethodPost, "https://echo.app.handletec.my",
    webhook.WithBearerToken("mysupersecrettoken"),
)
```

### Token (custom header)

`X-Api-Key: <value>` (or any header name you choose)

```go
whs := webhook.NewWebHooks()
_ = whs.Add(webhook.MethodPost, "https://echo.app.handletec.my",
    webhook.WithToken("X-Api-Key", "secret"),
)
```

If you load hooks from JSON/YAML and want to bind secrets at runtime:

```go
// Bind secrets at runtime (kept out of config files):
_ = whs.ApplyAuth(func(h *webhook.WebHook) error {
    switch h.AuthType {
    case webhook.AuthTypeBasic:
        user, pass := lookupBasic(h.Address)
        h.SetBasicAuth(user, pass)
    case webhook.AuthTypeBearer:
        token := lookupBearer(h.Address)
        h.SetBearerToken(token)
    case webhook.AuthTypeToken:
        value := lookupToken(h.Address)
        h.SetCustomToken(h.AuthHeaderName, value)
    case webhook.AuthTypeNone:
        // nothing
    }
    return nil
})
```

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

Headers are cloned per request for safe concurrent fan-out.

---

## GET and DELETE

`GET` and `DELETE` use the **query string**. If you also supply data via `WithData`/`WithJSON`, it will be **flattened into query parameters** (best effort: primitives → `k=v`, arrays → repeated keys, nested objects → JSON string).

```go
whs := webhook.NewWebHooks()
_ = whs.Add(webhook.MethodGet, "https://echo.app.handletec.my", webhook.WithNoAuth())

q := webhook.NewQuery()
q.Add("action", "create")
q.Add("timestamp", time.Now().Format(time.RFC3339))

tlsCfg := &tls.Config{InsecureSkipVerify: true}
hdrs := webhook.NewHeaders()
hdrs.SetUserAgent("my-agent/v1-get")


// You may provide both query AND data; data will be merged into the query for GET/DELETE.
_ = whs.Broadcast(tlsCfg, webhook.WithQuery(q), webhook.WithJSON(map[string]any{"extra": "value"}), webhook.WithHeaders(hdrs))
```

---

## Configuration (YAML / JSON)

Define your hooks in config, load them, then bind secrets at runtime.

```yaml
# example.yaml
webhooks:
  POST:
    - address: https://api.example.com/hookA         # shorthand item
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

After unmarshalling into `webhook.WebHooks`:

```go
err := webhooks.ApplyAuth(func(h *webhook.WebHook) error {
	  switch h.AuthType {
	  case webhook.AuthTypeBasic:
		  user, pass := lookupBasic(h.Address)
		  h.SetBasicAuth(user, pass)
	  case webhook.AuthTypeBearer:
		  token := lookupBearer(h.Address)
		  h.SetBearerToken(token)
	  case webhook.AuthTypeToken:
		  value := lookupToken(h.Address)
		  h.SetCustomToken(h.AuthHeaderName, value)
	  }
	  return nil
})
if err != nil {
	  log.Fatal(err)
}
```

---

## Adding and removing hooks

```go
whs := webhook.NewWebHooks()

// Add (dedupes by address per method)
_ = whs.Add(webhook.MethodPost, "https://api.example.com/hook", webhook.WithNoAuth())

// Remove
_ = whs.Remove(webhook.MethodPost, "https://api.example.com/hook")
```

---

## Request options and rules

Use options to describe what you’re sending:

- `WithData([]byte)` — raw JSON body (POST/PUT/PATCH) or data to be merged into query (GET/DELETE)
- `WithJSON(any)` — convenience: `json.Marshal` then treated like `WithData`
- `WithQuery(webhook.Query)` — additional query params (always preserved)
- `WithHeaders(webhook.Headers)` — extra headers

**Rules enforced by the library:**

- **POST/PUT/PATCH** require non-empty **data**.
- **GET/DELETE** never send an HTTP body; if **data** is supplied, it is **flattened into the query**.
- When a body is sent (POST/PUT/PATCH), the library sets  
  `Content-Type: application/json; charset=utf-8` and `Accept: application/json`.

> Note: unlike earlier versions, it is **valid to pass both** data and query in the same call.

---

## Concurrency and errors

- `Send`/`Broadcast` fan out concurrently using a bounded worker pool (based on `GOMAXPROCS`).
- Errors from multiple targets are aggregated and returned (Go 1.20+ `errors.Join`).

---

## TLS and timeouts

Pass a custom `*tls.Config` (custom roots, mTLS, etc.). Each request uses a 15s timeout.

```go
tlsCfg := &tls.Config{InsecureSkipVerify: true} // testing only
_ = whs.Broadcast(tlsCfg, webhook.WithData(body))
```

Do **not** enable `InsecureSkipVerify` in production.

---

## Examples mirrored from tests

### No auth, POST with JSON body

```go
whs := webhook.NewWebHooks()
_ = whs.Add(webhook.MethodPost, "https://echo.app.handletec.my", webhook.WithNoAuth())

tlsCfg := &tls.Config{InsecureSkipVerify: true}
hdrs := webhook.NewHeaders()
hdrs.SetUserAgent("my-agent/v1-noauth-post")


_ = whs.Broadcast(tlsCfg, webhook.WithData(b), webhook.WithHeaders(hdrs))
```

### Basic auth, POST with JSON body

```go
whs := webhook.NewWebHooks()
_ = whs.Add(webhook.MethodPost, "https://echo.app.handletec.my",
    webhook.WithBasicAuth("hello", "world"),
)

tlsCfg := &tls.Config{InsecureSkipVerify: true}
hdrs := webhook.NewHeaders()
hdrs.SetUserAgent("my-agent/v1-basicauth-post")


_ = whs.Broadcast(tlsCfg, webhook.WithData(b), webhook.WithHeaders(hdrs))
```

### Bearer auth, POST with JSON body

```go
whs := webhook.NewWebHooks()
_ = whs.Add(webhook.MethodPost, "https://echo.app.handletec.my",
    webhook.WithBearerToken("mysupersecrettoken"),
)

tlsCfg := &tls.Config{InsecureSkipVerify: true}
hdrs := webhook.NewHeaders()
hdrs.SetUserAgent("my-agent/v1-bearer-post")


_ = whs.Broadcast(tlsCfg, webhook.WithData(b), webhook.WithHeaders(hdrs))
```

### Custom token header, POST with JSON body

```go
whs := webhook.NewWebHooks()
_ = whs.Add(webhook.MethodPost, "https://echo.app.handletec.my",
    webhook.WithToken("X-Api-Key", "secret"),
)

tlsCfg := &tls.Config{InsecureSkipVerify: true}
hdrs := webhook.NewHeaders()
hdrs.SetUserAgent("my-agent/v1-token-post")


_ = whs.Broadcast(tlsCfg, webhook.WithData(b), webhook.WithHeaders(hdrs))
```

### GET with query parameters (plus extra data flattened)

```go
whs := webhook.NewWebHooks()
_ = whs.Add(webhook.MethodGet, "https://echo.app.handletec.my", webhook.WithNoAuth())

tlsCfg := &tls.Config{InsecureSkipVerify: true}
hdrs := webhook.NewHeaders()
hdrs.SetUserAgent("my-agent/v1-noauth-get")

// data is flattened into the query for GET
_ = whs.Broadcast(tlsCfg, webhook.WithQuery(q), webhook.WithJSON(map[string]any{"extra": "value"}), webhook.WithHeaders(hdrs))
```

---

## API overview

Construction:

```go
whs := webhook.NewWebHooks()
err := whs.Add(method, address, opt) // opt: WithNoAuth | WithBasicAuth | WithBearerToken | WithToken
err := whs.Remove(method, address)
```

Sending:

```go
// single method set
err := whs.Send(webhook.MethodPost, tlsCfg, webhook.WithData(body), webhook.WithHeaders(h))

// all methods
err := whs.Broadcast(tlsCfg, webhook.WithQuery(q), webhook.WithHeaders(h))
```

Request options:

```go
webhook.WithData([]byte)          // raw JSON body or data to flatten
webhook.WithJSON(any)             // marshal then treated like WithData
webhook.WithQuery(webhook.Query)  // url.Values
webhook.WithHeaders(webhook.Headers)
```

Auth options at construction:

```go
webhook.WithNoAuth()
webhook.WithBasicAuth(username, password)
webhook.WithBearerToken(token)
webhook.WithToken(headerName, value) // e.g., "X-Api-Key", "secret"
```

---

## Behavior and defaults

- `POST`, `PUT`, `PATCH` require a non-nil body. The library sets `Content-Type: application/json; charset=utf-8` and `Accept: application/json`.
- `GET`, `DELETE` ignore the body and rely on query parameters (if you pass `WithData/WithJSON`, it is flattened into the query).
- Headers passed by the caller are cloned per request.
- **Security:** Per-hook auth **overwrites** any global auth headers; hooks with `authType: none` **strip** auth headers to prevent leakage.
- Sends fan out concurrently; multiple errors are aggregated and returned.
- For testing you may use `InsecureSkipVerify` in a custom `tls.Config`. Don’t use it in production.
