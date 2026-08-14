/*
Copyright © 2025 Vicknesh Suppramaniam <vicknesh@handletec.my>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package webhook

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/svicknesh/httpclient"
	"gopkg.in/yaml.v3"
)

// defaultTimeout is used when a WebHook has no WithTimeout/SetTimeout
// override.
const defaultTimeout = 15 * time.Second

// WebHook - remote service to notify based
type WebHook struct {
	Enabled        bool     `yaml:"enabled" json:"enabled"`
	Method         Method   `yaml:"method" json:"method"`
	Address        string   `yaml:"address" json:"address"`
	AuthType       AuthType `yaml:"authType" json:"authType"`
	AuthHeaderName string   `yaml:"authHeaderName,omitempty" json:"authHeaderName,omitempty"`

	// for auth type basic
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`

	// for auth type token
	Token string `yaml:"token,omitempty" json:"token,omitempty"`

	basicAuthValue  string `yaml:"-" json:"-"`
	bearerAuthValue string `yaml:"-" json:"-"`
	tokenValue      string `yaml:"-" json:"-"`

	mu sync.RWMutex `yaml:"-" json:"-"`

	headers Headers `yaml:"-" json:"-"`

	// runtime-only delivery options; not part of the YAML/JSON config
	// schema -- set via HookOpt at construction (WithTimeout,
	// WithSuccessRange, WithRetry) or via the Set* methods at runtime.
	timeout    time.Duration `yaml:"-" json:"-"`
	successMin int           `yaml:"-" json:"-"`
	successMax int           `yaml:"-" json:"-"`
	retry      RetryPolicy   `yaml:"-" json:"-"`
}

// AuthBinderFunc is invoked once per hook; set creds via wh.SetBasicAuth / wh.SetBearerToken / wh.SetCustomToken as needed.
type AuthBinderFunc func(h *WebHook) error

// NewWebHook - creates new webhook. Options that set auth (WithBasicAuth,
// WithBearerToken, WithToken) are the secret-setting mechanism, so the
// compiled secret is required immediately -- unlike config-driven parsing
// (UnmarshalYAML/UnmarshalJSON), which allows a declared AuthType with a
// secret bound later via ApplyAuth.
func NewWebHook(method Method, address string, opt HookOpt) (*WebHook, error) {
	if err := urlCheck(address); err != nil {
		return nil, fmt.Errorf("new webhook: %w", err)
	}

	h := &WebHook{
		Enabled:        true,
		Method:         method,
		Address:        address,
		AuthType:       AuthTypeNone, // default
		AuthHeaderName: "",
	}

	// Apply the single option (if provided). The object isn't shared yet,
	// so no lock is needed here -- matches the pattern the With* HookOpt
	// constructors already use.
	if opt != nil {
		if err := opt(h); err != nil {
			return nil, err
		}
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Canonicalize any provided header name *before* compiling creds.
	if strings.TrimSpace(h.AuthHeaderName) != "" {
		h.AuthHeaderName = http.CanonicalHeaderKey(h.AuthHeaderName)
	}

	if err := validateAuthConfig(h); err != nil {
		return nil, fmt.Errorf("new webhook: %w", err)
	}

	// Compile plaintext config creds into private fields (and wipe them).
	if err := h.finalizeAuthLocked(); err != nil {
		return nil, fmt.Errorf("new webhook: %w", err)
	}

	switch h.AuthType {
	case AuthTypeBasic, AuthTypeBearer:
		// Always use Authorization for Basic/Bearer.
		h.AuthHeaderName = http.CanonicalHeaderKey("authorization")
	case AuthTypeNone, 0:
		h.AuthHeaderName = ""
	}

	// NewWebHook requires the secret immediately (see doc comment above).
	if err := authReady(h); err != nil {
		return nil, fmt.Errorf("new webhook: %w", err)
	}

	// Ensure only the active auth's derived value is kept.
	if h.AuthType != AuthTypeBasic {
		h.basicAuthValue = ""
	}
	if h.AuthType != AuthTypeBearer {
		h.bearerAuthValue = ""
	}
	if h.AuthType != AuthTypeToken {
		h.tokenValue = ""
	}

	return h, nil
}

func (wh *WebHook) String() (str string) {
	return json2str(wh)
}

func (wh *WebHook) MarshalYAML() (any, error) {

	wh.mu.RLock()
	enabled := wh.Enabled
	method := wh.Method
	address := wh.Address
	authType := wh.AuthType
	canonHeader := http.CanonicalHeaderKey(wh.AuthHeaderName)
	wh.mu.RUnlock()

	// Scalar shorthand if everything is at defaults:
	//   enabled: true
	//   method:  POST
	//   authType: none
	//   authHeaderName: "Authorization"
	if enabled &&
		(method == MethodPost || method == 0) &&
		(authType == AuthTypeNone || authType == 0) &&
		(canonHeader == "" || canonHeader == "Authorization") {
		return address, nil
	}

	// Secret-safe mapping (never emit Username/Password/Token or derived values).
	type out struct {
		Enabled        *bool     `yaml:"enabled,omitempty"`
		Method         *Method   `yaml:"method,omitempty"`
		Address        string    `yaml:"address"`
		AuthType       *AuthType `yaml:"authType,omitempty"`
		AuthHeaderName string    `yaml:"authHeaderName,omitempty"`
	}

	o := out{Address: address}

	if !enabled {
		v := false
		o.Enabled = &v
	}
	if method != 0 && method != MethodPost {
		m := method
		o.Method = &m
	}
	if authType != 0 && authType != AuthTypeNone {
		at := authType
		o.AuthType = &at
	}
	if canonHeader != "" && canonHeader != "Authorization" {
		o.AuthHeaderName = canonHeader
	}

	return o, nil
}

// UnmarshalYAML implements yaml.Unmarshaler for WebHook.
// Pointer receiver avoids copying the embedded RWMutex.
func (wh *WebHook) UnmarshalYAML(n *yaml.Node) error {
	if n == nil || n.Tag == "!!null" {
		*wh = WebHook{}
		return nil
	}

	switch n.Kind {
	case yaml.ScalarNode:
		// Shorthand: a single scalar is treated as the address with defaults.
		var addr string
		if err := n.Decode(&addr); err != nil {
			return fmt.Errorf("webhook: address decode at %d:%d: %w", n.Line, n.Column, err)
		}
		if err := urlCheck(addr); err != nil {
			return fmt.Errorf("webhook: invalid address %q at %d:%d: %w", addr, n.Line, n.Column, err)
		}

		// Reset field-by-field rather than `*wh = WebHook{...}` -- a
		// whole-struct assignment would replace wh.mu itself with a
		// fresh, unlocked mutex value while still holding the *old* one
		// locked, making the Unlock below panic ("Unlock of unlocked
		// RWMutex"). This was a real, pre-existing bug never exercised by
		// the previous test suite (which never parsed the scalar
		// shorthand via yaml.Unmarshal into a bare WebHook).
		wh.mu.Lock()
		wh.Enabled = true
		wh.Method = MethodPost
		wh.Address = addr
		wh.AuthType = AuthTypeNone
		wh.AuthHeaderName = ""
		wh.Username, wh.Password, wh.Token = "", "", ""
		wh.basicAuthValue, wh.bearerAuthValue, wh.tokenValue = "", "", ""
		wh.headers = nil
		wh.timeout = 0
		wh.successMin, wh.successMax = 0, 0
		wh.retry = RetryPolicy{}
		wh.mu.Unlock()
		return nil

	case yaml.MappingNode:
		// Decode only the public/config fields into a temp to avoid mutating while decoding.
		type in struct {
			Enabled        *bool    `yaml:"enabled"`
			Method         Method   `yaml:"method"`
			Address        string   `yaml:"address"`
			AuthType       AuthType `yaml:"authType"`
			AuthHeaderName string   `yaml:"authHeaderName"`

			Username string `yaml:"username"`
			Password string `yaml:"password"`
			Token    string `yaml:"token"`
		}
		var tmp in
		if err := n.Decode(&tmp); err != nil {
			return fmt.Errorf("webhook: mapping decode at %d:%d: %w", n.Line, n.Column, err)
		}

		// Defaults
		enabled := true
		if tmp.Enabled != nil {
			enabled = *tmp.Enabled
		}
		method := tmp.Method
		if method == 0 {
			method = MethodPost
		}
		authType := tmp.AuthType
		if authType == 0 {
			authType = AuthTypeNone
		}

		// Validate address
		addr := strings.TrimSpace(tmp.Address)
		if addr == "" {
			return fmt.Errorf("webhook: address is required at %d:%d", n.Line, n.Column)
		}
		if err := urlCheck(addr); err != nil {
			return fmt.Errorf("webhook: invalid address %q at %d:%d: %w", addr, n.Line, n.Column, err)
		}

		// Canonicalize header name early.
		authHeader := tmp.AuthHeaderName
		if strings.TrimSpace(authHeader) != "" {
			authHeader = http.CanonicalHeaderKey(authHeader)
		}

		// Apply under lock; then finalize & validate.
		wh.mu.Lock()

		wh.Enabled = enabled
		wh.Method = method
		wh.Address = addr
		wh.AuthType = authType
		wh.AuthHeaderName = authHeader

		// Stash plaintext (to be compiled & wiped).
		wh.Username = tmp.Username
		wh.Password = tmp.Password
		wh.Token = tmp.Token

		// Structural check only -- config never needs to embed the actual
		// secret for any auth type. Deferred secret binding happens later
		// via ApplyAuth/Set*.
		if err := validateAuthConfig(wh); err != nil {
			wh.mu.Unlock()
			return fmt.Errorf("webhook: %w at %d:%d", err, n.Line, n.Column)
		}

		// Compile plaintext creds into derived fields (if present), then wipe.
		if err := wh.finalizeAuthLocked(); err != nil {
			wh.mu.Unlock()
			return fmt.Errorf("webhook: auth finalize at %d:%d: %w", n.Line, n.Column, err)
		}

		switch wh.AuthType {
		case AuthTypeBasic, AuthTypeBearer:
			// Always use Authorization for Basic/Bearer.
			wh.AuthHeaderName = http.CanonicalHeaderKey("authorization")
		case AuthTypeNone, 0:
			// ensure no leftovers from prior state
			wh.basicAuthValue, wh.bearerAuthValue, wh.tokenValue = "", "", ""
		}

		// Scrub non-active derived values (defense-in-depth).
		if wh.AuthType != AuthTypeBasic {
			wh.basicAuthValue = ""
		}
		if wh.AuthType != AuthTypeBearer {
			wh.bearerAuthValue = ""
		}
		if wh.AuthType != AuthTypeToken {
			wh.tokenValue = ""
		}

		wh.mu.Unlock()
		return nil

	default:
		return fmt.Errorf("webhook: expected scalar or mapping at %d:%d", n.Line, n.Column)
	}
}

// Send - sends the request to the endpoint using context.Background().
// See SendContext for the full behavior and the concurrency contract.
func (wh *WebHook) Send(tlsConfig *tls.Config, body []byte, query Query, headers Headers) error {
	return wh.SendContext(context.Background(), tlsConfig, body, query, headers)
}

// SendContext sends the request to the endpoint using ctx for cancellation
// and deadlines.
//
// SendContext takes exactly one coherent snapshot of every piece of
// mutable per-hook delivery state under a single wh.mu.RLock() critical
// section (Enabled, Method, Address, AuthType, AuthHeaderName, the bound
// credential for the active auth type, persistent per-hook headers cloned
// while still locked, timeout, success range, and retry policy), then
// releases the lock immediately. All URL processing, header/auth
// validation, request construction, retries, and network I/O happen after
// RUnlock() -- never while holding wh.mu. This guarantees a single call
// never observes a mix of old/new state (e.g. old auth type paired with a
// new credential, or an old retry policy paired with a new method) even if
// a supported setter (SetBasicAuth, SetBearerToken, SetCustomToken,
// SetHeader, SetRetry) runs concurrently.
func (wh *WebHook) SendContext(ctx context.Context, tlsConfig *tls.Config, body []byte, query Query, headers Headers) error {
	if ctx == nil {
		ctx = context.Background()
	}

	// --- single coherent snapshot, one RLock/RUnlock pair ---
	wh.mu.RLock()
	enabled := wh.Enabled
	method := wh.Method
	address := wh.Address
	authType := wh.AuthType
	authHeaderName := wh.AuthHeaderName
	basic := wh.basicAuthValue
	bearer := wh.bearerAuthValue
	token := wh.tokenValue
	var persistentHeaders Headers
	if wh.headers != nil {
		persistentHeaders = wh.headers.Clone()
	}
	timeout := wh.timeout
	successMin := wh.successMin
	successMax := wh.successMax
	retryPolicy := wh.retry
	wh.mu.RUnlock()
	// --- snapshot released; everything below uses only local values ---

	if !enabled {
		return nil
	}

	if method == 0 || method.String() == "unknown" {
		return fmt.Errorf("webhook: unsupported method provided")
	}

	if strings.TrimSpace(address) == "" {
		return fmt.Errorf("webhook: address is empty")
	}

	// Defense-in-depth: Method stays an exported, directly-writable field
	// for compatibility, so it can legally be mutated after SetRetry ran
	// its own construction-time check against a different Method. Re-check
	// the snapshotted (Method, RetryPolicy) pair here, before any network
	// I/O, so a non-idempotent method can never silently retry.
	if err := checkNonIdempotentRetry(method, retryPolicy); err != nil {
		return fmt.Errorf("webhook: %w", err)
	}

	// Fail closed: if AuthType requires a credential and none is bound,
	// refuse to send rather than silently going out unauthenticated.
	if err := authReadyValues(authType, authHeaderName, basic, bearer, token); err != nil {
		return &DeliveryError{Target: redactURL(address), Method: method, Err: err}
	}

	if err := urlCheck(address); err != nil {
		return fmt.Errorf("webhook: invalid address: %w", err)
	}

	// Build final URL with merged query (preserve any existing query in Address).
	u, err := url.Parse(address)
	if err != nil {
		return fmt.Errorf("webhook: parse address: %w", err)
	}
	q := u.Query()
	// Last-write-wins per key: WithQuery's values overwrite any same-key
	// values already present in the address's own query string, matching
	// the precedence the JSON-flatten stage below already provides (q.Set
	// semantics) rather than appending onto them (which would leave
	// url.Values.Get -- which returns the *first* value -- resolving to
	// the address's value instead of the caller-supplied one).
	for k, vs := range query {
		if len(vs) == 0 {
			continue
		}
		cp := make([]string, len(vs))
		copy(cp, vs)
		q[k] = cp
	}

	// POST, PUT, PATCH uses body; GET, DELETE uses query param
	usesBody := method == MethodPost || method == MethodPut || method == MethodPatch

	var payload io.Reader
	if usesBody {
		if len(body) == 0 {
			return fmt.Errorf("webhook: payload cannot be empty for method %q", method)
		}
		payload = bytes.NewReader(body)
	} else {
		// For GET/DELETE, flatten any JSON body into query and send no HTTP body.
		if err := mergeJSONIntoQuery(q, body); err != nil {
			return fmt.Errorf("webhook: invalid JSON payload for query flattening: %w", err)
		}
		payload = nil
	}

	u.RawQuery = q.Encode()

	// Split into a base (scheme://host[:port]) and an endpoint (path?query)
	// -- httpclient.NewRequest treats its address argument as a base that
	// Custom's endpoint argument is appended to, so passing the same full
	// URL as both (as the previous implementation did) doubles the path.
	base := u.Scheme + "://" + u.Host
	endpoint := u.RequestURI()

	// Clone headers per request so we don't mutate caller state.
	reqHeaders := headers.Clone()

	// Merge per-hook persistent headers (already cloned under the snapshot
	// above); caller-supplied headers take precedence.
	if persistentHeaders != nil {
		merged := persistentHeaders.Clone()
		for _, kv := range reqHeaders {
			merged.Set(kv.Key, kv.Value)
		}
		reqHeaders = merged
	}

	// Inject/enforce the auth header. Per-hook auth always wins over any
	// caller-supplied header of the same name, and a caller can never leak
	// an Authorization header into a hook that isn't Basic/Bearer.
	switch authType {
	case AuthTypeBasic:
		reqHeaders.Set("Authorization", basic)
	case AuthTypeBearer:
		reqHeaders.Set("Authorization", bearer)
	case AuthTypeToken:
		reqHeaders.Del("Authorization")
		if authHeaderName != "" {
			reqHeaders.Set(authHeaderName, token)
		}
	case AuthTypeNone, 0:
		reqHeaders.Del("Authorization")
	}

	if payload != nil {
		reqHeaders.Set("Content-Type", "application/json; charset=utf-8")
		reqHeaders.Set("Accept", "application/json")
	}

	if err := validateOutboundHeaders(reqHeaders); err != nil {
		return fmt.Errorf("webhook: %w", err)
	}

	if timeout <= 0 {
		timeout = defaultTimeout
	}

	// A fresh httpclient.Request is built for every call; see the
	// README's "Transport reuse" section for why this is a documented
	// dependency limitation and not a design choice -- httpclient.Request
	// is not safe to share/cache across calls or goroutines.
	client := httpclient.NewRequest(base, timeout, tlsConfig, reqHeaders.asHTTPClient())
	client.RetryConfig = retryPolicy.toHTTPClientRetryConfig()

	// Redirects are never followed, for every hook regardless of auth type.
	// The configured Address is always the final destination -- a 3xx
	// response is returned to us as an ordinary Response (via httpclient's
	// CheckRedirect policy of http.ErrUseLastResponse) instead of being
	// followed, so Authorization/custom auth headers are never forwarded to
	// a redirect target. The existing status-range check below classifies
	// an unfollowed 3xx exactly like any other non-2xx status; see README's
	// "Security Limitations" section.
	client.DisableRedirects()

	resp, err := client.Custom(ctx, method.String(), endpoint, payload)
	if err != nil {
		return &DeliveryError{
			Target: redactURL(address),
			Method: method,
			// Transport-level failures are never retried by httpclient
			// (confirmed by reading its connect()), so this is never
			// retryable regardless of RetryOn.
			Retryable: false,
			Err:       err,
		}
	}

	if !statusIsSuccess(resp.StatusCode, successMin, successMax) {
		return &DeliveryError{
			Target:     redactURL(address),
			Method:     method,
			StatusCode: resp.StatusCode,
			Retryable:  containsIntSlice(retryPolicy.effectiveRetryOn(), resp.StatusCode),
			Err:        fmt.Errorf("unexpected status code %d", resp.StatusCode),
		}
	}

	return nil
}

// SetBasicAuth - Authorization: Basic <base64(username:password)>
func (wh *WebHook) SetBasicAuth(username, password string) {
	wh.mu.Lock()
	defer wh.mu.Unlock()
	wh.setBasicAuthLocked(username, password)
}

// setBasicAuthLocked assumes the caller already holds wh.mu.
func (wh *WebHook) setBasicAuthLocked(username, password string) {
	raw := strings.TrimSpace(username) + ":" + password
	enc := base64.StdEncoding.EncodeToString([]byte(raw))
	wh.AuthType = AuthTypeBasic
	wh.AuthHeaderName = http.CanonicalHeaderKey("authorization")
	wh.basicAuthValue = "Basic " + enc
}

// SetBearerToken - Authorization: Bearer <token>  (JWT or opaque token)
func (wh *WebHook) SetBearerToken(token string) {
	wh.mu.Lock()
	defer wh.mu.Unlock()
	wh.setBearerTokenLocked(token)
}

// setBearerTokenLocked assumes the caller already holds wh.mu.
func (wh *WebHook) setBearerTokenLocked(token string) {
	wh.AuthType = AuthTypeBearer
	wh.AuthHeaderName = http.CanonicalHeaderKey("authorization")
	wh.bearerAuthValue = "Bearer " + strings.TrimSpace(token)
}

// SetCustomToken - sets custom header with value e.g., X-Api-Key: <value>
func (wh *WebHook) SetCustomToken(headerName, value string) {
	wh.mu.Lock()
	defer wh.mu.Unlock()
	wh.setCustomTokenLocked(headerName, value)
}

// setCustomTokenLocked assumes the caller already holds wh.mu.
func (wh *WebHook) setCustomTokenLocked(headerName, value string) {
	wh.AuthType = AuthTypeToken
	wh.AuthHeaderName = http.CanonicalHeaderKey(headerName)
	wh.tokenValue = value
}

// finalizeAuthLocked compiles plaintext config credentials (Username,
// Password, Token) into the private, compiled auth fields and wipes the
// plaintext afterwards. It only ever calls *Locked helpers -- never the
// public, locking Set* methods -- since sync.RWMutex is not reentrant and
// calling a locking method here would self-deadlock. The caller must
// already hold wh.mu.Lock() (NewWebHook, UnmarshalYAML's mapping branch,
// UnmarshalJSON, and ApplyAuth all hold it explicitly around this call).
func (wh *WebHook) finalizeAuthLocked() error {
	switch wh.AuthType {
	case AuthTypeBasic:
		if wh.Username != "" || wh.Password != "" {
			wh.setBasicAuthLocked(wh.Username, wh.Password)
		}
	case AuthTypeBearer:
		if strings.TrimSpace(wh.Token) != "" {
			wh.setBearerTokenLocked(wh.Token)
		}
	case AuthTypeToken:
		if wh.AuthHeaderName == "" {
			return fmt.Errorf("token auth requires AuthHeaderName")
		}
		if strings.TrimSpace(wh.Token) != "" {
			wh.setCustomTokenLocked(wh.AuthHeaderName, wh.Token)
		}
	}
	// wipe plaintext
	wh.Username, wh.Password, wh.Token = "", "", ""
	return nil
}

// validateAuthConfig performs a structural check only: is AuthType a known
// value, and for token auth, is a header name declared? It does not
// require a secret to be present -- config files (YAML/JSON) only ever
// need to declare AuthType (+ header name for token); the real secret is
// bound later via ApplyAuth or the Set* methods. Runs at parse/
// construction time (NewWebHook, UnmarshalYAML, UnmarshalJSON).
func validateAuthConfig(wh *WebHook) error {
	switch wh.AuthType {
	case AuthTypeBasic, AuthTypeBearer, AuthTypeNone, 0:
		return nil
	case AuthTypeToken:
		if strings.TrimSpace(wh.AuthHeaderName) == "" {
			return fmt.Errorf("token auth requires authHeaderName")
		}
		return nil
	default:
		return fmt.Errorf("unsupported auth type %q", wh.AuthType.String())
	}
}

// authReady is the delivery-readiness check: is the compiled secret for
// the declared AuthType actually present? It reads wh's fields directly
// with no internal locking -- callers must already hold an appropriate
// lock (ApplyAuth, NewWebHook) or otherwise know the value isn't
// concurrently shared. Runs at send time (fail-closed, via
// authReadyValues against SendContext's own snapshot) and in ApplyAuth
// after the binder runs.
func authReady(wh *WebHook) error {
	return authReadyValues(wh.AuthType, wh.AuthHeaderName, wh.basicAuthValue, wh.bearerAuthValue, wh.tokenValue)
}

// authReadyValues is the value-based form of authReady, used by
// SendContext against its own single-snapshot values so the readiness
// check never re-reads wh's (possibly since-changed) live fields.
func authReadyValues(authType AuthType, authHeaderName, basic, bearer, token string) error {
	switch authType {
	case AuthTypeBasic:
		if strings.TrimSpace(basic) == "" {
			return fmt.Errorf("basic auth declared but no credential bound")
		}
	case AuthTypeBearer:
		if strings.TrimSpace(bearer) == "" {
			return fmt.Errorf("bearer auth declared but no token bound")
		}
	case AuthTypeToken:
		if strings.TrimSpace(authHeaderName) == "" {
			return fmt.Errorf("token auth declared but no header name set")
		}
		if strings.TrimSpace(token) == "" {
			return fmt.Errorf("token auth declared but no token value bound")
		}
	case AuthTypeNone, 0:
		// nothing required
	default:
		return fmt.Errorf("unsupported auth type %q", authType.String())
	}
	return nil
}

// SetHeader sets or overwrites a persistent default header for this WebHook instance.
// These headers are merged into every Send()/SendContext() call, unless
// explicitly overridden by WithHeaders.
func (wh *WebHook) SetHeader(name, value string) {
	wh.mu.Lock()
	defer wh.mu.Unlock()
	wh.setHeaderLocked(name, value)
}

// setHeaderLocked assumes the caller already holds wh.mu.
func (wh *WebHook) setHeaderLocked(name, value string) {
	if wh.headers == nil {
		wh.headers = NewHeaders()
	}
	wh.headers.Set(name, value)
}

// jsonWebHookOut is the shape emitted by MarshalJSON -- secret-safe: it
// never includes Username/Password/Token or any compiled secret value.
type jsonWebHookOut struct {
	Enabled        bool     `json:"enabled"`
	Method         Method   `json:"method,omitempty"`
	Address        string   `json:"address"`
	AuthType       AuthType `json:"authType,omitempty"`
	AuthHeaderName string   `json:"authHeaderName,omitempty"`
}

// MarshalJSON implements json.Marshaler for WebHook. It shares
// validateAuthConfig/authReady/finalizeAuthLocked with the YAML path, and
// -- like MarshalYAML -- never emits Username/Password/Token or any
// compiled secret value.
func (wh *WebHook) MarshalJSON() ([]byte, error) {
	wh.mu.RLock()
	out := jsonWebHookOut{
		Enabled:        wh.Enabled,
		Method:         wh.Method,
		Address:        wh.Address,
		AuthType:       wh.AuthType,
		AuthHeaderName: wh.AuthHeaderName,
	}
	wh.mu.RUnlock()
	return json.Marshal(out)
}

// jsonWebHookIn is the shape accepted by UnmarshalJSON. It includes the
// plaintext credential fields so config files can declare (but need not
// populate) auth secrets; they are compiled via finalizeAuthLocked and
// wiped immediately after decoding, same as the YAML mapping path.
type jsonWebHookIn struct {
	Enabled        *bool    `json:"enabled"`
	Method         Method   `json:"method"`
	Address        string   `json:"address"`
	AuthType       AuthType `json:"authType"`
	AuthHeaderName string   `json:"authHeaderName"`
	Username       string   `json:"username"`
	Password       string   `json:"password"`
	Token          string   `json:"token"`
}

// UnmarshalJSON implements json.Unmarshaler for WebHook, at parity with
// UnmarshalYAML: validates structurally (validateAuthConfig, no secret
// required), compiles any plaintext Username/Password/Token into the
// private, compiled auth fields via finalizeAuthLocked, and wipes the
// plaintext -- fixing the previous complete absence of JSON support, which
// left plaintext secrets uncompiled and unwiped on the struct.
func (wh *WebHook) UnmarshalJSON(data []byte) error {
	var tmp jsonWebHookIn
	if err := json.Unmarshal(data, &tmp); err != nil {
		return fmt.Errorf("webhook: json decode: %w", err)
	}

	enabled := true
	if tmp.Enabled != nil {
		enabled = *tmp.Enabled
	}
	method := tmp.Method
	if method == 0 {
		method = MethodPost
	}
	authType := tmp.AuthType
	if authType == 0 {
		authType = AuthTypeNone
	}

	addr := strings.TrimSpace(tmp.Address)
	if addr == "" {
		return fmt.Errorf("webhook: address is required")
	}
	if err := urlCheck(addr); err != nil {
		return fmt.Errorf("webhook: invalid address %q: %w", addr, err)
	}

	authHeader := tmp.AuthHeaderName
	if strings.TrimSpace(authHeader) != "" {
		authHeader = http.CanonicalHeaderKey(authHeader)
	}

	wh.mu.Lock()

	wh.Enabled = enabled
	wh.Method = method
	wh.Address = addr
	wh.AuthType = authType
	wh.AuthHeaderName = authHeader
	wh.Username = tmp.Username
	wh.Password = tmp.Password
	wh.Token = tmp.Token

	if err := validateAuthConfig(wh); err != nil {
		wh.mu.Unlock()
		return fmt.Errorf("webhook: %w", err)
	}

	if err := wh.finalizeAuthLocked(); err != nil {
		wh.mu.Unlock()
		return fmt.Errorf("webhook: auth finalize: %w", err)
	}

	switch wh.AuthType {
	case AuthTypeBasic, AuthTypeBearer:
		wh.AuthHeaderName = http.CanonicalHeaderKey("authorization")
	case AuthTypeNone, 0:
		wh.basicAuthValue, wh.bearerAuthValue, wh.tokenValue = "", "", ""
	}

	if wh.AuthType != AuthTypeBasic {
		wh.basicAuthValue = ""
	}
	if wh.AuthType != AuthTypeBearer {
		wh.bearerAuthValue = ""
	}
	if wh.AuthType != AuthTypeToken {
		wh.tokenValue = ""
	}

	wh.mu.Unlock()
	return nil
}
