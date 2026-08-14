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
	"encoding/json"
	"fmt"
)

type reqSpec struct {
	body        []byte
	query       Query
	headers     Headers
	concurrency int
}

func (s *reqSpec) validate() error {
	if s.headers == nil {
		s.headers = NewHeaders() // your default UA, etc.
	}
	return nil
}

type ReqOpt func(*reqSpec) error

// WithData - body payload. The slice is copied immediately when this
// function is called (not deferred to send time), so the caller may
// safely mutate or reuse the original slice after WithData returns.
func WithData(b []byte) ReqOpt {
	cp := append([]byte(nil), b...)
	return func(s *reqSpec) error { s.body = cp; return nil }
}

func WithJSON(v any) ReqOpt {
	return func(s *reqSpec) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		s.body = b
		return nil
	}
}

// WithQuery - query parameters. The url.Values are cloned immediately when
// this function is called, so the caller may safely mutate the original
// after WithQuery returns.
func WithQuery(q Query) ReqOpt {
	cp := cloneQuery(q)
	return func(s *reqSpec) error { s.query = cp; return nil }
}

// WithHeaders - headers for the HTTP request. The headers are cloned
// immediately when this function is called, so the caller may safely
// mutate the original after WithHeaders returns.
func WithHeaders(h Headers) ReqOpt {
	cp := h.Clone()
	return func(s *reqSpec) error { s.headers = cp; return nil }
}

// WithConcurrency overrides the default fan-out concurrency
// (runtime.GOMAXPROCS(0)*4) used by Send/Broadcast and their Context
// variants.
func WithConcurrency(n int) ReqOpt {
	return func(s *reqSpec) error {
		if n <= 0 {
			return fmt.Errorf("concurrency must be positive, got %d", n)
		}
		s.concurrency = n
		return nil
	}
}
