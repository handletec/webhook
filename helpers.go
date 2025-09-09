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

// urlCheck - validates a url pattern
func urlCheck(u string) (err error) {
	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("url parse error -> %w", err)
	}

	if len(parsed.Scheme) == 0 {
		return fmt.Errorf("url scheme error -> %w", err)
	}

	if len(parsed.Host) == 0 {
		return fmt.Errorf("url host error -> %w", err)
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

/*
func bufferPayload(r io.Reader) (data []byte, error error) {
	if r == nil {
		return nil, nil
	}
	return io.ReadAll(r)
}
*/

// fanout executes Send on all hooks concurrently with a concurrency limit.
func fanout(hooks []*WebHook, tlsCfg *tls.Config, body []byte, query Query, headers Headers, limit int) error {
	g := new(errgroup.Group)
	if limit > 0 {
		g.SetLimit(limit)
	}

	var mu sync.Mutex
	var errs []error

	for _, wh := range hooks {
		if wh == nil || !wh.Enabled {
			continue
		}
		h := wh // capture

		g.Go(func() error {
			if err := h.Send(tlsCfg, body, query, headers); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s %s: %w", h.Method.String(), h.Address, err))
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

/*
func detectContentType(body []byte) string {
	b := bytes.TrimSpace(body)
	if len(b) == 0 {
		return "application/octet-stream"
	}

	// JSON?
	if (b[0] == '{' || b[0] == '[') && json.Valid(b) {
		return "application/json"
	}

	// application/x-www-form-urlencoded?
	if v, err := url.ParseQuery(string(b)); err == nil && len(v) > 0 {
		return "application/x-www-form-urlencoded"
	}

	// XML? (very simple heuristic)
	if b[0] == '<' {
		return "application/xml"
	}

	// Otherwise let Go guess (first 512 bytes)
	ct := http.DetectContentType(b)
	// If it guessed octet-stream but it’s valid UTF-8 text, call it text/plain
	if ct == "application/octet-stream" && utf8.Valid(b) {
		return "text/plain; charset=utf-8"
	}
	return ct
}
*/

// mergeJSONIntoQuery - merge JSON payload (bytes) into query params (best-effort, flat)
func mergeJSONIntoQuery(q url.Values, body []byte) {
	if len(body) == 0 {
		return
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return // ignore if not JSON; caller controls body
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
}
