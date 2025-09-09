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
	"crypto/tls"
	"encoding/base64"
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
}

// AuthBinderFunc is invoked once per hook; set creds via wh.SetBasicAuth / wh.SetBearerToken / wh.SetCustomToken as needed.
type AuthBinderFunc func(h *WebHook) error

// NewWebHook - creates new webhook
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

	// Apply the single option (if provided).
	if opt != nil {
		if err := opt(h); err != nil {
			return nil, err
		}
	}

	// Canonicalize any provided header name *before* compiling creds.
	if strings.TrimSpace(h.AuthHeaderName) != "" {
		h.AuthHeaderName = http.CanonicalHeaderKey(h.AuthHeaderName)
	}

	// Compile plaintext config creds into private fields (and wipe them).
	if err := h.finalizeAuthFromConfig(); err != nil {
		return nil, err
	}

	// Finalize / validate auth settings.
	switch h.AuthType {
	case AuthTypeBasic:
		// Always use Authorization for Basic
		h.AuthHeaderName = http.CanonicalHeaderKey("authorization")
		if strings.TrimSpace(h.basicAuthValue) == "" {
			return nil, fmt.Errorf("basic auth requires username/password")
		}

	case AuthTypeBearer:
		// Always use Authorization for Bearer
		h.AuthHeaderName = http.CanonicalHeaderKey("authorization")
		if strings.TrimSpace(h.bearerAuthValue) == "" {
			return nil, fmt.Errorf("bearer token is required")
		}

	case AuthTypeToken:
		// Must have both header name and compiled token value
		if strings.TrimSpace(h.AuthHeaderName) == "" {
			return nil, fmt.Errorf("token auth requires authHeaderName")
		}
		if strings.TrimSpace(h.tokenValue) == "" {
			return nil, fmt.Errorf("token auth requires non-empty token value")
		}

	case AuthTypeNone, 0:
		// Ensure nothing leaks
		h.basicAuthValue, h.bearerAuthValue, h.tokenValue = "", "", ""
		if h.AuthHeaderName != "" {
			// keep user-provided header name only if explicitly desired; usually safe to clear
			h.AuthHeaderName = ""
		}

	default:
		return nil, fmt.Errorf("unsupported auth type %q", h.AuthType.String())
	}

	// Optional: ensure only the active auth’s derived value is kept
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

		wh.mu.Lock()
		*wh = WebHook{
			Enabled:  true,
			Method:   MethodPost,
			Address:  addr,
			AuthType: AuthTypeNone,
			// mu is preserved (we're replacing the struct contents while locked)
		}
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

		// Compile plaintext creds into derived fields, then wipe.
		if err := wh.finalizeAuthFromConfig(); err != nil {
			wh.mu.Unlock()
			return fmt.Errorf("webhook: auth finalize at %d:%d: %w", n.Line, n.Column, err)
		}

		// Force standard header for Basic/Bearer; validate presence.
		switch wh.AuthType {
		case AuthTypeBasic:
			wh.AuthHeaderName = http.CanonicalHeaderKey("authorization")
			if strings.TrimSpace(wh.basicAuthValue) == "" {
				wh.mu.Unlock()
				return fmt.Errorf("webhook: basic auth requires username/password at %d:%d", n.Line, n.Column)
			}

		case AuthTypeBearer:
			wh.AuthHeaderName = http.CanonicalHeaderKey("authorization")
			/*
				if strings.TrimSpace(wh.bearerAuthValue) == "" {
					wh.mu.Unlock()
					return fmt.Errorf("webhook: bearer token is required at %d:%d", n.Line, n.Column)
				}
			*/

		case AuthTypeToken:
			if strings.TrimSpace(wh.AuthHeaderName) == "" || strings.TrimSpace(wh.tokenValue) == "" {
				wh.mu.Unlock()
				return fmt.Errorf("webhook: token auth requires authHeaderName and token at %d:%d", n.Line, n.Column)
			}

		case AuthTypeNone, 0:
			// ensure no leftovers from prior state
			wh.basicAuthValue, wh.bearerAuthValue, wh.tokenValue = "", "", ""

		default:
			wh.mu.Unlock()
			return fmt.Errorf("webhook: unsupported authType %q at %d:%d", wh.AuthType.String(), n.Line, n.Column)
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

// Send - sends the request to the endpoint, no response returned - fire and forget
func (wh *WebHook) Send(tlsConfig *tls.Config, body []byte, query Query, headers Headers) (err error) {
	if !wh.Enabled {
		return nil
	}

	if wh.Method.String() == "unknown" {
		return fmt.Errorf("unsupported method provided")
	}

	if strings.TrimSpace(wh.Address) == "" {
		return fmt.Errorf("webhook address is empty")
	}
	if _, err := url.ParseRequestURI(wh.Address); err != nil {
		return fmt.Errorf("invalid webhook address: %w", err)
	}

	// Build final URL with merged query (preserve any existing query in Address).
	u, err := url.Parse(wh.Address)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}
	q := u.Query()
	for k, vs := range query {
		for _, v := range vs {
			q.Add(k, v)
		}
	}

	// POST, PUT, PATCH uses body; GET, DELETE uses query param
	usesBody := wh.Method == MethodPost || wh.Method == MethodPut || wh.Method == MethodPatch

	var payload io.Reader
	if usesBody {
		if len(body) == 0 {
			return fmt.Errorf("payload cannot be empty for method %q", wh.Method)
		}
		payload = bytes.NewReader(body)
	} else {
		// For GET/DELETE, flatten any JSON body into query and send no HTTP body.
		mergeJSONIntoQuery(q, body)
		payload = nil
	}

	u.RawQuery = q.Encode()
	finalURL := u.String()

	/*
		// Enforce body rules and build payload reader.
		var payload io.Reader
		switch wh.Method {
		case MethodPost, MethodPut, MethodPatch:
			if body == nil {
				return fmt.Errorf("payload cannot be empty for method %q", wh.Method)
			}
			payload = bytes.NewReader(body)
		case MethodGet, MethodDelete:
			payload = nil
		default:
			// If you later add methods, decide here.
		}
	*/

	// Clone headers per request so we don't mutate caller state.
	reqHeaders := headers.Clone()

	// Merge per-hook defaults under read lock; caller headers take precedence.
	wh.mu.RLock()
	if wh.headers != nil {
		merged := wh.headers.Clone()
		for _, kv := range reqHeaders {
			merged.Set(kv.Key, kv.Value)
		}
		reqHeaders = merged
	}
	wh.mu.RUnlock()

	wh.mu.RLock()
	authType := wh.AuthType
	authHeaderName := wh.AuthHeaderName
	basic := wh.basicAuthValue
	bearer := wh.bearerAuthValue
	token := wh.tokenValue
	wh.mu.RUnlock()

	// Inject auth header automatically if caller hasn't set it.
	switch authType {
	case AuthTypeBasic:
		if basic != "" {
			reqHeaders.Set("Authorization", basic)
		} else {
			reqHeaders.Del("Authorization")
		}
	case AuthTypeBearer:
		if bearer != "" {
			reqHeaders.Set("Authorization", bearer)
		} else {
			reqHeaders.Del("Authorization")
		}
	case AuthTypeToken:
		if authHeaderName != "" {
			if token != "" {
				reqHeaders.Set(authHeaderName, token)
			} else {
				reqHeaders.Del(authHeaderName)
			}
		}
	case AuthTypeNone, 0:
		reqHeaders.Del("Authorization")
		if authHeaderName != "" {
			reqHeaders.Del(authHeaderName)
		}
	}

	if payload != nil {
		reqHeaders.Set("Content-Type", "application/json; charset=utf-8")
		reqHeaders.Set("Accept", "application/json")
	}

	client := httpclient.NewRequest(finalURL, 15*time.Second, tlsConfig, reqHeaders.asHTTPClient())

	// Use the same finalURL for the request (not wh.Address).
	if _, err := client.Custom(wh.Method.String(), finalURL, payload); err != nil {
		return fmt.Errorf("request error %q %q - %w", wh.Method, finalURL, err)
	}
	return nil // for webhook, its fire and forget, we don't do return values
}

// SetBasicAuth - Authorization: Basic <base64(username:password)>
func (wh *WebHook) SetBasicAuth(username, password string) {
	raw := strings.TrimSpace(username) + ":" + password
	enc := base64.StdEncoding.EncodeToString([]byte(raw))
	wh.AuthType = AuthTypeBasic
	wh.AuthHeaderName = http.CanonicalHeaderKey("authorization")
	wh.basicAuthValue = "Basic " + enc
}

// SetBearerToken - Authorization: Bearer <token>  (JWT or opaque token)
func (wh *WebHook) SetBearerToken(token string) {
	wh.AuthType = AuthTypeBearer
	wh.AuthHeaderName = http.CanonicalHeaderKey("authorization")
	wh.bearerAuthValue = "Bearer " + strings.TrimSpace(token)
}

// SetCustomToken - sets custom headwe with value e.g., X-Api-Key: <value>
func (wh *WebHook) SetCustomToken(headerName, value string) {
	wh.AuthType = AuthTypeToken
	wh.AuthHeaderName = http.CanonicalHeaderKey(headerName)
	wh.tokenValue = value
}

func (wh *WebHook) finalizeAuthFromConfig() error {
	switch wh.AuthType {
	case AuthTypeBasic:
		if wh.Username != "" || wh.Password != "" {
			wh.SetBasicAuth(wh.Username, wh.Password)
		}
	case AuthTypeToken:
		if wh.AuthHeaderName == "" {
			return fmt.Errorf("token auth requires AuthHeaderName")
		}
		if strings.TrimSpace(wh.Token) != "" {
			wh.SetCustomToken(wh.AuthHeaderName, wh.Token)
		}
		/*
			case AuthTypeBearer:
				if strings.TrimSpace(wh.Token) != "" {
					wh.SetBearerToken(wh.Token)
				}
		*/
	}
	// wipe plaintext
	wh.Username, wh.Password, wh.Token = "", "", ""
	return nil
}

// SetHeader sets or overwrites a persistent default header for this WebHook instance.
// These headers are merged into every Send() call, unless explicitly overridden by WithHeaders.
func (wh *WebHook) SetHeader(name, value string) {
	wh.mu.Lock()
	defer wh.mu.Unlock()
	if wh.headers == nil {
		wh.headers = NewHeaders()
	}
	wh.headers.Set(name, value)
}
