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
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type HookOpt func(*WebHook) error

// WithNoAuth - no authentication needed for remote endpoint
func WithNoAuth() HookOpt {
	return func(h *WebHook) error {
		h.AuthType = AuthTypeNone
		h.AuthHeaderName = ""
		h.basicAuthValue, h.bearerAuthValue, h.tokenValue = "", "", ""
		return nil
	}
}

// WithBasicAuth - Authorization: Basic <base64(username:password)>
func WithBasicAuth(username, password string) HookOpt {
	return func(h *WebHook) error {
		raw := strings.TrimSpace(username) + ":" + password
		enc := base64.StdEncoding.EncodeToString([]byte(raw))
		h.AuthType = AuthTypeBasic
		h.AuthHeaderName = http.CanonicalHeaderKey("authorization")
		h.basicAuthValue = "Basic " + enc
		return nil
	}
}

// WithBearerToken - Authorization: Bearer <token> (JWT or opaque)
func WithBearerToken(token string) HookOpt {
	return func(h *WebHook) error {
		h.AuthType = AuthTypeBearer
		h.AuthHeaderName = http.CanonicalHeaderKey("authorization")
		h.bearerAuthValue = "Bearer " + strings.TrimSpace(token)
		return nil
	}
}

// WithToken - Custom header token, e.g. X-Api-Key: <value>
func WithToken(headerName, value string) HookOpt {
	return func(h *WebHook) error {
		headerName = strings.TrimSpace(headerName)
		if headerName == "" {
			return fmt.Errorf("header name required for token auth")
		}
		h.AuthType = AuthTypeToken
		h.AuthHeaderName = http.CanonicalHeaderKey(headerName)
		h.tokenValue = value
		return nil
	}
}

// WithTimeout overrides the default per-request timeout (15s) used when
// dispatching this hook.
func WithTimeout(d time.Duration) HookOpt {
	return func(h *WebHook) error {
		if d <= 0 {
			return fmt.Errorf("timeout must be positive, got %v", d)
		}
		h.timeout = d
		return nil
	}
}

// WithSuccessRange overrides the default success range (2xx) used to
// determine whether a response counts as a successful delivery. Requires
// 100 <= min <= max <= 599.
func WithSuccessRange(min, max int) HookOpt {
	return func(h *WebHook) error {
		if min < 100 || max > 599 || min > max {
			return fmt.Errorf("invalid success range [%d,%d]: require 100 <= min <= max <= 599", min, max)
		}
		h.successMin = min
		h.successMax = max
		return nil
	}
}
