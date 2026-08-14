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
	"net/url"
)

// DeliveryError represents a failed webhook delivery attempt.
//
// Target is redacted to scheme://host[:port] only -- it never includes the
// path or query string, since secrets (tokens, signed URLs) can appear in
// either. Use redactURL to produce it consistently.
type DeliveryError struct {
	Target     string // redacted: scheme://host[:port]
	Method     Method
	StatusCode int  // 0 when the failure occurred before/without an HTTP response
	Retryable  bool // best-effort diagnostic hint; does not affect dispatch
	Err        error
}

func (e *DeliveryError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("webhook delivery failed: %s %s -> status %d: %v", e.Method.String(), e.Target, e.StatusCode, e.Err)
	}
	return fmt.Sprintf("webhook delivery failed: %s %s: %v", e.Method.String(), e.Target, e.Err)
}

// Unwrap exposes the underlying cause so errors.Is/errors.As (e.g. against
// context.Canceled or context.DeadlineExceeded) still work through this
// wrapper.
func (e *DeliveryError) Unwrap() error {
	return e.Err
}

// redactURL parses raw and rebuilds it as scheme://host[:port] only,
// unconditionally dropping userinfo, path, and query. If raw cannot be
// parsed or lacks a scheme/host, a fixed placeholder is returned so a
// delivery failure never echoes unparsed, potentially secret-bearing input
// back into an error message or aggregated log.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "(unparseable address)"
	}
	return u.Scheme + "://" + u.Host
}
