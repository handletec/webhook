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
	"fmt"
	"time"

	"github.com/svicknesh/httpclient"
)

// RetryPolicy configures opt-in retry behavior for a WebHook. The zero
// value disables retry entirely (MaxAttempts 0 or 1 means a single
// attempt, no retry) -- retry is off by default.
//
// Retry is scoped to exactly what github.com/svicknesh/httpclient supports;
// this is a hard dependency limitation, not a design choice:
//
//   - Status-code based only. Only HTTP responses whose status code
//     appears in RetryOn (default [429, 500, 502, 503, 504] when retry is
//     active and RetryOn is nil, matching httpclient's own default) are
//     retried.
//   - Network/transport-level errors (connection refused, DNS failure,
//     TLS handshake failure, context deadline during dial, etc.) are
//     NEVER retried -- confirmed by reading httpclient's connect(): on a
//     transport error it returns immediately ("Transport error — do not
//     retry") without entering the retry loop.
//   - Retry-After response headers are not honored in any way -- the
//     dependency has no support for it.
type RetryPolicy struct {
	// MaxAttempts is the total number of attempts, including the first.
	// 0 or 1 disables retry.
	MaxAttempts int

	// BaseDelay is the initial backoff delay. httpclient defaults to
	// 500ms when zero and retry is active.
	BaseDelay time.Duration

	// MaxDelay caps the backoff delay. httpclient defaults to 30s when
	// zero and retry is active.
	MaxDelay time.Duration

	// Multiplier is the exponential growth factor. httpclient defaults to
	// 2.0 when zero and retry is active.
	Multiplier float64

	// Jitter adds +/-50% randomness to the computed delay.
	Jitter bool

	// RetryOn is the list of HTTP status codes that trigger a retry. nil
	// defaults to [429, 500, 502, 503, 504] when MaxAttempts > 1.
	RetryOn []int

	// AllowNonIdempotentRetry must be true to enable MaxAttempts > 1 on a
	// hook whose Method is POST or PATCH. Without it, construction fails
	// closed rather than silently retrying a non-idempotent request.
	AllowNonIdempotentRetry bool
}

// validate rejects nonsensical configuration values at construction time.
// Values are never silently clamped.
func (p RetryPolicy) validate() error {
	if p.MaxAttempts < 0 {
		return fmt.Errorf("retry policy: MaxAttempts cannot be negative, got %d", p.MaxAttempts)
	}
	if p.BaseDelay < 0 {
		return fmt.Errorf("retry policy: BaseDelay cannot be negative, got %v", p.BaseDelay)
	}
	if p.MaxDelay < 0 {
		return fmt.Errorf("retry policy: MaxDelay cannot be negative, got %v", p.MaxDelay)
	}
	if p.Multiplier != 0 && p.Multiplier < 1 {
		return fmt.Errorf("retry policy: Multiplier must be >= 1 when set, got %v", p.Multiplier)
	}
	for _, code := range p.RetryOn {
		if code < 100 || code > 599 {
			return fmt.Errorf("retry policy: RetryOn contains invalid HTTP status code %d", code)
		}
	}
	return nil
}

// checkNonIdempotentRetry enforces that retry is never enabled for
// non-idempotent methods (POST, PATCH) unless the caller has explicitly
// acknowledged the risk via AllowNonIdempotentRetry.
//
// It is deliberately called in two places: once at WithRetry/SetRetry
// construction time (against the Method known at that moment), and again
// inside SendContext against the single coherent snapshot of
// (Method, RetryPolicy) taken under wh.mu.RLock(). Method stays an
// exported, directly-writable field for compatibility with existing
// consumers, so it can legally be mutated after SetRetry already ran its
// own check against a different Method -- the second, dispatch-time check
// is what actually guarantees the guard holds.
func checkNonIdempotentRetry(method Method, policy RetryPolicy) error {
	if policy.MaxAttempts > 1 && (method == MethodPost || method == MethodPatch) && !policy.AllowNonIdempotentRetry {
		return fmt.Errorf(
			"retry policy: MaxAttempts=%d on non-idempotent method %s requires AllowNonIdempotentRetry=true",
			policy.MaxAttempts, method.String(),
		)
	}
	return nil
}

// WithRetry sets the retry policy at construction time via NewWebHook.
func WithRetry(policy RetryPolicy) HookOpt {
	return func(h *WebHook) error {
		if err := policy.validate(); err != nil {
			return err
		}
		if err := checkNonIdempotentRetry(h.Method, policy); err != nil {
			return err
		}
		h.retry = policy
		return nil
	}
}

// SetRetry sets or replaces the retry policy for an existing WebHook.
func (wh *WebHook) SetRetry(policy RetryPolicy) error {
	wh.mu.Lock()
	defer wh.mu.Unlock()
	return wh.setRetryLocked(policy)
}

// setRetryLocked assumes the caller already holds wh.mu.
func (wh *WebHook) setRetryLocked(policy RetryPolicy) error {
	if err := policy.validate(); err != nil {
		return err
	}
	if err := checkNonIdempotentRetry(wh.Method, policy); err != nil {
		return err
	}
	wh.retry = policy
	return nil
}

// toHTTPClientRetryConfig translates the policy directly onto the
// dependency's RetryConfig fields for the freshly-built, per-call Request
// (no sharing/caching concerns -- see README's transport-reuse
// limitation).
func (p RetryPolicy) toHTTPClientRetryConfig() httpclient.RetryConfig {
	return httpclient.RetryConfig{
		MaxAttempts: p.MaxAttempts,
		RetryOn:     p.RetryOn,
		BaseDelay:   p.BaseDelay,
		MaxDelay:    p.MaxDelay,
		Multiplier:  p.Multiplier,
		Jitter:      p.Jitter,
	}
}

// effectiveRetryOn returns the status codes that would trigger a retry,
// applying httpclient's own default when RetryOn is nil and retry is
// active. Used only to annotate DeliveryError.Retryable for diagnostics --
// it does not itself affect dispatch behavior.
func (p RetryPolicy) effectiveRetryOn() []int {
	if p.RetryOn != nil {
		return p.RetryOn
	}
	if p.MaxAttempts > 1 {
		return []int{429, 500, 502, 503, 504}
	}
	return nil
}
