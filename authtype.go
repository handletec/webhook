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

type AuthType uint8

const (
	// AuthTypeNone - no authentication required
	AuthTypeNone = iota + 1
	// AuthTypeBasic - username password combination
	AuthTypeBasic
	// AuthTypeBearer - bearer token authentication
	AuthTypeBearer
	// AuthType - uses custom token authentication
	AuthTypeToken
)

func (at AuthType) String() (str string) {
	return enum2str.String(at, "unknown", "none", "basic", "bearer", "token")
}

func (at *AuthType) MarshalJSON() (data []byte, err error) {
	return json.Marshal(at.String())
}

func (at *AuthType) UnmarshalJSON(data []byte) (err error) {

	atStr, err := strconv.Unquote(string(data))
	if err != nil {
		atStr = strings.Trim(string(data), "\"")
	}

	return setAuthTypeFromString(at, atStr)
}

func (at AuthType) MarshalYAML() (any, error) {
	// Emit YAML null when unset; else the lowercase string token.
	if at == 0 {
		return nil, nil
	}
	return at.String(), nil
}

func (at *AuthType) UnmarshalYAML(n *yaml.Node) error {
	if n == nil || n.Tag == "!!null" || strings.TrimSpace(n.Value) == "" {
		*at = 0
		return nil
	}
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("authType: expected a string at %d:%d", n.Line, n.Column)
	}
	// Reject integers explicitly
	if n.Tag == "!!int" {
		return fmt.Errorf("authType: must be a string (none|basic|bearer|token), not an integer at %d:%d", n.Line, n.Column)
	}
	return setAuthTypeFromString(at, n.Value)
}
