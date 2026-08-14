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
	"net/http"
	"runtime"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// WebHooks - collection of `WebHook`
type WebHooks map[Method][]*WebHook

// NewWebHooks - create new instance of webhooks to store multiple webhook for different HTTP methods
func NewWebHooks() (whs WebHooks) {
	return make(WebHooks)
}

// Add - adds a new webhook
func (whs WebHooks) Add(method Method, address string, opt HookOpt) error {
	if whs == nil {
		return fmt.Errorf("webhooks map is nil (call NewWebHooks() first)")
	}

	// de-dup by address for this method
	for _, wh := range whs[method] {
		if wh != nil && strings.EqualFold(wh.Address, address) {
			return nil // already present
		}
	}

	wh, err := NewWebHook(method, address, opt)
	if err != nil {
		return err
	}

	whs[method] = append(whs[method], wh)
	return nil
}

// Remove - Removes an existing webhook
func (whs WebHooks) Remove(method Method, address string) (err error) {
	hooks := whs[method]

	for i, wh := range whs[method] {
		if strings.EqualFold(wh.Address, address) {
			// remove index i
			copy(hooks[i:], hooks[i+1:])
			hooks = hooks[:len(hooks)-1]
			whs[method] = hooks
			return nil
		}
	}

	return fmt.Errorf("webhook not found for method=%s address=%s", method.String(), address)
}

func (whs *WebHooks) String() (str string) {
	return json2str(whs)
}

func (whs WebHooks) MarshalYAML() (any, error) {
	// Build: map[method][]item
	out := make(map[string]any, len(whs))

	for m, hooks := range whs {
		if m == 0 || len(hooks) == 0 {
			continue
		}
		key := m.String()
		if strings.TrimSpace(key) == "" {
			continue
		}

		items := make([]any, 0, len(hooks))
		for _, h := range hooks {
			if h == nil {
				continue
			}

			// Snapshot under read lock to avoid races and avoid copying the mutex by value.
			h.mu.RLock()
			enabled := h.Enabled
			method := h.Method
			address := h.Address
			authType := h.AuthType
			canonHeader := http.CanonicalHeaderKey(h.AuthHeaderName)
			h.mu.RUnlock()

			if strings.TrimSpace(address) == "" {
				continue
			}

			// Inside a method-keyed list, we can serialize to scalar when defaults are used:
			// enabled: true, authType: none, authHeaderName: "Authorization"
			// (Method is implied by the key.)
			if enabled &&
				(authType == 0 || authType == AuthTypeNone) &&
				(canonHeader == "" || canonHeader == "Authorization") {
				items = append(items, address)
				continue
			}

			// Otherwise emit a minimal mapping (omit method if it matches key).
			type outItem struct {
				Enabled        *bool     `yaml:"enabled,omitempty"`
				Method         *Method   `yaml:"method,omitempty"`
				Address        string    `yaml:"address"`
				AuthType       *AuthType `yaml:"authType,omitempty"`
				AuthHeaderName string    `yaml:"authHeaderName,omitempty"`
			}

			oi := outItem{Address: address}

			if !enabled {
				v := false
				oi.Enabled = &v
			}
			if method != m && method != 0 {
				mv := method
				oi.Method = &mv
			}
			if authType != 0 && authType != AuthTypeNone {
				at := authType
				oi.AuthType = &at
			}
			if canonHeader != "" && canonHeader != "Authorization" {
				oi.AuthHeaderName = canonHeader
			}

			items = append(items, oi)
		}

		if len(items) > 0 {
			out[key] = items
		}
	}

	return out, nil
}

func (whs WebHooks) MarshalJSON() ([]byte, error) {
	out := make(map[string][]*WebHook, len(whs))
	for m, hooks := range whs {
		if m == 0 || len(hooks) == 0 {
			continue
		}
		key := m.String()
		if key == "" || key == "unknown" {
			continue
		}
		out[key] = hooks
	}
	return json.Marshal(out)
}

// parseMethodKey accepts both canonical method names ("POST") and legacy
// raw-integer-string keys ("2") for backward compatibility with output
// produced by the earlier, broken default encoding/json map-key handling
// (Go only consults MarshalJSON for map values, not keys, unless the key
// type implements encoding.TextMarshaler, which Method does not -- so a
// bare map[Method][]*WebHook serialized with the stdlib default would have
// emitted raw integer keys).
func parseMethodKey(key string) (Method, error) {
	var m Method
	if err := setMethodFromString(&m, key); err == nil && m != 0 {
		return m, nil
	}
	n, convErr := strconv.Atoi(key)
	if convErr != nil || n < int(MethodGet) || n > int(MethodDelete) {
		return 0, fmt.Errorf("unsupported method key %q", key)
	}
	return Method(n), nil
}

func (whs *WebHooks) UnmarshalJSON(data []byte) error {
	var raw map[string][]*WebHook
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("webhooks: json decode: %w", err)
	}

	result := make(WebHooks)
	for key, hooks := range raw {
		m, err := parseMethodKey(key)
		if err != nil {
			return fmt.Errorf("webhooks: %w", err)
		}
		for _, h := range hooks {
			if h == nil {
				continue
			}
			if !existsByAddress(result[m], h.Address) {
				result[m] = append(result[m], h)
			}
		}
	}
	*whs = result
	return nil
}

func (whs *WebHooks) UnmarshalYAML(n *yaml.Node) error {
	result := make(WebHooks)

	switch n.Kind {
	case yaml.MappingNode:
		if len(n.Content)%2 != 0 {
			return fmt.Errorf("webhooks: malformed mapping at %d:%d", n.Line, n.Column)
		}
		for i := 0; i < len(n.Content); i += 2 {
			keyNode := n.Content[i]
			valNode := n.Content[i+1]

			var methodKey string
			if err := keyNode.Decode(&methodKey); err != nil {
				return fmt.Errorf("webhooks: method key decode at %d:%d: %w", keyNode.Line, keyNode.Column, err)
			}
			var m Method
			if err := setMethodFromString(&m, methodKey); err != nil {
				return fmt.Errorf("webhooks: %w at %d:%d", err, keyNode.Line, keyNode.Column)
			}

			// Normalize value to a slice of item nodes
			var items []*yaml.Node
			switch valNode.Kind {
			case yaml.SequenceNode:
				items = valNode.Content
			case yaml.ScalarNode, yaml.MappingNode:
				items = []*yaml.Node{valNode}
			default:
				return fmt.Errorf("webhooks: method %q expects list or item at %d:%d", methodKey, valNode.Line, valNode.Column)
			}

			for _, it := range items {
				var hook WebHook
				if err := it.Decode(&hook); err != nil {
					return fmt.Errorf("webhooks: hook decode at %d:%d: %w", it.Line, it.Column, err)
				}

				// If item explicitly has "method", ensure it matches the key
				if hasMethodKey(it) && hook.Method != m {
					return fmt.Errorf("webhooks: method mismatch (%s key vs %s in item) at %d:%d",
						m.String(), hook.Method.String(), it.Line, it.Column)
				}
				// Inherit key method if not explicitly set in item
				if !hasMethodKey(it) {
					hook.Method = m
				}

				// Dedup by address (case-insensitive) within the method
				if !existsByAddress(result[m], hook.Address) {
					// DO NOT copy structs with mutex by value; append the address of the loop-local.
					result[m] = append(result[m], &hook)
				}
			}
		}

	case yaml.SequenceNode:
		for _, it := range n.Content {
			var hook WebHook
			if err := it.Decode(&hook); err != nil {
				return fmt.Errorf("webhooks: hook decode at %d:%d: %w", it.Line, it.Column, err)
			}
			if hook.Method == 0 {
				return fmt.Errorf("webhooks: each item must include a valid 'method' at %d:%d", it.Line, it.Column)
			}
			m := hook.Method
			if !existsByAddress(result[m], hook.Address) {
				// Append pointer directly to avoid copying the mutex.
				result[m] = append(result[m], &hook)
			}
		}

	default:
		return fmt.Errorf("webhooks: unsupported YAML at %d:%d (need mapping or sequence)", n.Line, n.Column)
	}

	*whs = result
	return nil
}

// Send - sends the request to all addresses for a given method (concurrently)
// using context.Background(). See SendContext for the context-aware form.
func (whs WebHooks) Send(method Method, tlsCfg *tls.Config, opts ...ReqOpt) error {
	return whs.SendContext(context.Background(), method, tlsCfg, opts...)
}

// SendContext sends the request to all addresses for a given method
// (concurrently), using ctx for cancellation and deadlines.
func (whs WebHooks) SendContext(ctx context.Context, method Method, tlsCfg *tls.Config, opts ...ReqOpt) error {
	hooks := whs[method]
	if len(hooks) == 0 {
		return nil
	}

	spec := &reqSpec{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(spec); err != nil {
			return err
		}
	}
	if err := spec.validate(); err != nil {
		return err
	}

	limit := spec.concurrency
	if limit <= 0 {
		limit = runtime.GOMAXPROCS(0) * 4
	}

	return fanout(ctx, hooks, tlsCfg, spec.body, spec.query, spec.headers, limit)
}

// Broadcast - sends the request to all addresses across all methods
// (concurrently) using context.Background(). See BroadcastContext for the
// context-aware form.
func (whs WebHooks) Broadcast(tlsCfg *tls.Config, opts ...ReqOpt) error {
	return whs.BroadcastContext(context.Background(), tlsCfg, opts...)
}

// BroadcastContext sends the request to all addresses across all methods
// (concurrently), using ctx for cancellation and deadlines.
func (whs WebHooks) BroadcastContext(ctx context.Context, tlsCfg *tls.Config, opts ...ReqOpt) error {
	// flatten once
	total := 0
	for _, list := range whs {
		total += len(list)
	}
	if total == 0 {
		return nil
	}
	flat := make([]*WebHook, 0, total)
	for _, list := range whs {
		flat = append(flat, list...)
	}

	spec := &reqSpec{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(spec); err != nil {
			return err
		}
	}
	if err := spec.validate(); err != nil {
		return err
	}

	limit := spec.concurrency
	if limit <= 0 {
		limit = runtime.GOMAXPROCS(0) * 4
	}

	return fanout(ctx, flat, tlsCfg, spec.body, spec.query, spec.headers, limit)
}

// ApplyAuth - applies credentials to every hook using the provided binder.
func (whs *WebHooks) ApplyAuth(binder AuthBinderFunc) error {
	if whs == nil || *whs == nil {
		return nil
	}
	if binder == nil {
		return fmt.Errorf("auth binder cannot be nil")
	}

	var errs []error
	for _, list := range *whs {
		for _, h := range list {
			if h == nil || !h.Enabled {
				continue
			}

			// Let the caller bind secrets however they like (may set plaintext or call Set*).
			// binder is called without holding h.mu -- it may itself call the
			// public, locking Set* methods.
			if err := binder(h); err != nil {
				errs = append(errs, fmt.Errorf("%s %s: %w", h.Method.String(), redactURL(h.Address), err))
				continue
			}

			// mutate under exclusive lock
			h.mu.Lock()

			// Canonicalize header (binder may have set it).
			if strings.TrimSpace(h.AuthHeaderName) != "" {
				h.AuthHeaderName = http.CanonicalHeaderKey(h.AuthHeaderName)
			}

			// Compile & wipe any plaintext creds set via config fields.
			if err := h.finalizeAuthLocked(); err != nil {
				h.mu.Unlock()
				errs = append(errs, fmt.Errorf("%s %s: %w", h.Method.String(), redactURL(h.Address), err))
				continue
			}

			switch h.AuthType {
			case AuthTypeBasic, AuthTypeBearer:
				// Force standard header for Basic/Bearer.
				h.AuthHeaderName = http.CanonicalHeaderKey("authorization")
			}

			// Delivery-readiness check, shared with SendContext's fail-closed
			// gate -- surfaces the same error class instead of a hand-copied
			// per-type switch.
			if err := authReady(h); err != nil {
				errs = append(errs, fmt.Errorf("%s %s: %w", h.Method.String(), redactURL(h.Address), err))
			}

			// Scrub non-active derived values to avoid stale leftovers.
			if h.AuthType != AuthTypeBasic {
				h.basicAuthValue = ""
			}
			if h.AuthType != AuthTypeBearer {
				h.bearerAuthValue = ""
			}
			if h.AuthType != AuthTypeToken {
				h.tokenValue = ""
			}

			h.mu.Unlock()
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
