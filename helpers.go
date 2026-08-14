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
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

// urlCheck - validates a url pattern. Only http/https schemes are allowed,
// a host is required, and embedded userinfo (e.g. "https://user:pass@host")
// is rejected -- credentials belong in the auth mechanisms, not the URL.
func urlCheck(u string) (err error) {
	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("url parse error -> %w", err)
	}

	switch parsed.Scheme {
	case "http", "https":
		// allowed
	default:
		return fmt.Errorf("url scheme error -> unsupported scheme %q (only http/https allowed)", parsed.Scheme)
	}

	if len(parsed.Host) == 0 {
		return fmt.Errorf("url host error -> host is required")
	}

	if parsed.User != nil {
		return fmt.Errorf("url error -> embedded userinfo is not allowed")
	}

	return nil
}

func setMethodFromString(m *Method, s string) error {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "GET":
		*m = MethodGet
	case "POST":
		*m = MethodPost
	case "PUT":
		*m = MethodPut
	case "PATCH":
		*m = MethodPatch
	case "DELETE":
		*m = MethodDelete
	case "":
		*m = 0
	default:
		return fmt.Errorf("unsupported method %q (allowed: GET, POST, PUT, PATCH, DELETE)", s)
	}
	return nil
}

func setAuthTypeFromString(at *AuthType, s string) error {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "none":
		*at = AuthTypeNone
	case "basic":
		*at = AuthTypeBasic
	case "bearer":
		*at = AuthTypeBearer
	case "token":
		*at = AuthTypeToken
	case "":
		*at = 0 // unset
	default:
		return fmt.Errorf("unsupported auth type %q (allowed: none, basic, bearer, token)", s)
	}
	return nil
}

// json2str - convers a json object to string
func json2str(obj any) (str string) {
	data, err := json.Marshal(obj)
	if nil != err {
		return "{}" // if an error occured, return an empty json string
	}
	return string(data)
}

func hasMethodKey(n *yaml.Node) (exist bool) {
	if n.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if strings.EqualFold(n.Content[i].Value, "method") {
			return true
		}
	}
	return false
}

func existsByAddress(list []*WebHook, addr string) (exist bool) {
	for _, w := range list {
		if strings.EqualFold(w.Address, addr) {
			return true
		}
	}
	return false
}

// fanout executes SendContext on all hooks concurrently with a concurrency
// limit. Each hook's own SendContext snapshot decides whether it is
// enabled, so no Enabled pre-filter is needed here.
func fanout(ctx context.Context, hooks []*WebHook, tlsCfg *tls.Config, body []byte, query Query, headers Headers, limit int) error {
	g := new(errgroup.Group)
	if limit > 0 {
		g.SetLimit(limit)
	}

	var mu sync.Mutex
	var errs []error

	for _, wh := range hooks {
		if wh == nil {
			continue
		}
		h := wh // capture

		g.Go(func() error {
			if err := h.SendContext(ctx, tlsCfg, body, query, headers); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s %s: %w", h.Method.String(), redactURL(h.Address), err))
				mu.Unlock()
			}
			return nil
		})
	}

	_ = g.Wait()
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// mergeJSONIntoQuery merges a flat JSON payload (bytes) into query
// parameters (best-effort; nested objects are re-encoded as a single JSON
// string value). Returns an error when body is non-empty and not valid
// JSON -- callers must surface this rather than silently dropping data.
func mergeJSONIntoQuery(q url.Values, body []byte) error {
	if len(body) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	for k, v := range m {
		switch t := v.(type) {
		case nil:
			// skip
		case string:
			q.Set(k, t)
		case float64, bool:
			q.Set(k, fmt.Sprint(t))
		case []any:
			for _, it := range t {
				q.Add(k, fmt.Sprint(it))
			}
		default:
			// nested object: JSON-encode once
			b, _ := json.Marshal(t)
			q.Set(k, string(b))
		}
	}
	return nil
}

// cloneQuery returns a shallow copy of q's url.Values (mirrors
// Headers.Clone()) -- safe to pass to goroutines / retain independently of
// the caller's map.
func cloneQuery(q Query) Query {
	if q == nil {
		return nil
	}
	out := make(Query, len(q))
	for k, vs := range q {
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[k] = cp
	}
	return out
}

// validateOutboundHeaders is the single choke point for outbound header
// validation, called once in SendContext immediately before dispatch. It
// covers both persistent per-hook headers and caller-supplied headers
// (already merged by the time this runs).
func validateOutboundHeaders(h Headers) error {
	for _, kv := range h {
		if !isValidHTTPToken(kv.Key) {
			return fmt.Errorf("invalid header name %q", kv.Key)
		}
		if strings.ContainsAny(kv.Value, "\r\n") {
			return fmt.Errorf("invalid header value for %q: contains CR/LF", kv.Key)
		}
	}
	return nil
}

// isValidHTTPToken reports whether s is a valid RFC 7230 "token"
// (1*tchar), as required for HTTP header field names.
func isValidHTTPToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !isTChar(r) {
			return false
		}
	}
	return true
}

// isTChar reports whether r is an RFC 7230 tchar:
// "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
// "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
func isTChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		return true
	default:
		return false
	}
}

// statusIsSuccess reports whether status falls within the configured
// success range. A zero min/max pair means "unset" and falls back to the
// default 2xx range.
func statusIsSuccess(status, min, max int) bool {
	if min == 0 && max == 0 {
		return status >= 200 && status <= 299
	}
	return status >= min && status <= max
}

// containsIntSlice reports whether code appears in codes.
func containsIntSlice(codes []int, code int) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}
