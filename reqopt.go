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
)

type reqSpec struct {
	body    []byte
	query   Query
	headers Headers
}

func (s *reqSpec) validate() error {
	/*
		if s.body != nil && s.query != nil && len(s.query) > 0 {
			return fmt.Errorf("cannot specify both body and query")
		}
	*/
	if s.headers == nil {
		s.headers = NewHeaders() // your default UA, etc.
	}
	return nil
}

type ReqOpt func(*reqSpec) error

// WithData - body payload
func WithData(b []byte) ReqOpt {
	return func(s *reqSpec) error { s.body = b; return nil }
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

// WithQuery - query parameters
func WithQuery(q Query) ReqOpt {
	return func(s *reqSpec) error { s.query = q; return nil }
}

// WithHeaders - headers for the HTTP
func WithHeaders(h Headers) ReqOpt {
	return func(s *reqSpec) error { s.headers = h; return nil }
}
