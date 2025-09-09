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
	"net/http"
	"strings"

	"github.com/svicknesh/httpclient"
)

type Headers httpclient.Headers

// NewHeaders - initialize headers with default user-agent
func NewHeaders() (h Headers) {
	h = make(Headers, 0)
	h.SetUserAgent("go-webhook/v1")
	return h
}

// Clone returns a shallow copy of the slice (safe to pass to goroutines).
func (h Headers) Clone() Headers {
	if h == nil {
		return nil
	}
	out := make(Headers, len(h))
	copy(out, h)
	return out
}

// asHTTPClient converts to the underlying type when calling the client.
func (h Headers) asHTTPClient() httpclient.Headers {
	return httpclient.Headers(h)
}

// Get returns the first value for name (case-insensitive) and true if found.
func (h Headers) Get(name string) (string, bool) {
	for i := range h {
		if strings.EqualFold(h[i].Key, name) {
			return h[i].Value, true
		}
	}
	return "", false
}

// Add appends a header without removing existing ones.
func (h *Headers) Add(name, value string) {
	if h == nil {
		return
	}
	canon := http.CanonicalHeaderKey(name)
	*h = append(*h, httpclient.Header{Key: canon, Value: value})
}

// Set sets/overwrites the header (keeps only one entry for that name).
func (h *Headers) Set(name, value string) {
	if h == nil {
		return
	}
	canon := http.CanonicalHeaderKey(name)

	// Find first match; overwrite its value and remove any duplicates.
	found := -1
	s := *h
	for i := 0; i < len(s); i++ {
		if strings.EqualFold(s[i].Key, canon) {
			if found == -1 {
				s[i].Value = value
				found = i
			} else {
				// delete duplicate entry i
				s = append(s[:i], s[i+1:]...)
				i--
			}
		}
	}
	if found == -1 { // not found -> append
		s = append(s, httpclient.Header{Key: canon, Value: value})
	}
	*h = s
}

// Del removes all instances of the header name (case-insensitive).
func (h *Headers) Del(name string) {
	if h == nil || *h == nil {
		return
	}
	canon := http.CanonicalHeaderKey(name)
	s := *h
	dst := s[:0]
	for i := range s {
		if !strings.EqualFold(s[i].Key, canon) {
			dst = append(dst, s[i])
		}
	}
	// zero tail to avoid holding references (optional)
	for i := len(dst); i < len(s); i++ {
		s[i] = httpclient.Header{}
	}
	*h = dst
}

// Convenience
func (h *Headers) SetUserAgent(ua string) { h.Set("User-Agent", ua) }
