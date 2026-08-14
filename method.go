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
	"strconv"
	"strings"

	"github.com/svicknesh/enum2str"
	"gopkg.in/yaml.v3"
)

type Method uint8

const (
	// MethodGet - HTTP GET Method
	MethodGet = iota + 1
	// Method - HTTP POST Method
	MethodPost
	// Method - HTTP PUT Method
	MethodPut
	// Method - HTTP PATCH Method
	MethodPatch
	// Method - HTTP DELETE Method
	MethodDelete
)

func (method Method) String() (str string) {
	return enum2str.String(method, "unknown", "GET", "POST", "PUT", "PATCH", "DELETE")
}

// MarshalJSON uses a value receiver (matching MarshalYAML) so it applies
// even when a Method value is embedded non-addressably in another struct
// (e.g. json.Marshal(someStructValue) without taking its address) --
// confirmed necessary: a pointer-receiver MarshalJSON is silently skipped
// by encoding/json for non-addressable values, falling back to encoding
// the raw uint8 instead of the method name.
func (method Method) MarshalJSON() (data []byte, err error) {
	return json.Marshal(method.String())
}

func (method *Method) UnmarshalJSON(data []byte) (err error) {

	methodStr, err := strconv.Unquote(string(data))
	if err != nil {
		methodStr = strings.Trim(string(data), "\"")
	}

	return setMethodFromString(method, methodStr)
}

func (m Method) MarshalYAML() (any, error) {
	if m == 0 {
		return nil, nil // emit YAML null if unset
	}
	return m.String(), nil
}

func (m *Method) UnmarshalYAML(n *yaml.Node) error {
	if n == nil || n.Tag == "!!null" || strings.TrimSpace(n.Value) == "" {
		*m = 0
		return nil
	}
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("method: expected a string at %d:%d", n.Line, n.Column)
	}
	// Reject integers explicitly
	if n.Tag == "!!int" {
		return fmt.Errorf("method: must be a string name (GET|POST|PUT|PATCH|DELETE), not an integer at %d:%d", n.Line, n.Column)
	}
	return setMethodFromString(m, n.Value)
}
