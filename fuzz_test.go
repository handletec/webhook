package webhook_test

import (
	"encoding/json"
	"testing"

	"github.com/handletec/webhook"
	"gopkg.in/yaml.v3"
)

// FuzzNewWebHookAddress fuzzes address parsing/validation (urlCheck, via
// NewWebHook, its only exported entry point). The property under test:
// NewWebHook must never panic regardless of input, and must never return
// both a non-nil *WebHook and a non-nil error.
func FuzzNewWebHookAddress(f *testing.F) {
	seeds := []string{
		"https://example.test/hook",
		"http://example.test:8080/a?b=c",
		"ftp://example.test/a",
		"javascript:alert(1)",
		"https://user:pass@example.test/a",
		"not a url at all",
		"",
		"https://",
		"https://[::1]:9999/x",
		"https://example.test/" + string(rune(0)),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, address string) {
		wh, err := webhook.NewWebHook(webhook.MethodGet, address, webhook.WithNoAuth())
		if err != nil {
			if wh != nil {
				t.Fatalf("NewWebHook(%q) returned both a non-nil WebHook and an error: %v", address, err)
			}
			return
		}
		if wh == nil {
			t.Fatalf("NewWebHook(%q) returned nil WebHook with nil error", address)
		}
	})
}

// FuzzWebHooksConfigDecode fuzzes YAML/JSON config decoding. The property
// under test: neither yaml.Unmarshal nor json.Unmarshal into *WebHooks
// may ever panic, regardless of input -- they must always either succeed
// or return an error.
func FuzzWebHooksConfigDecode(f *testing.F) {
	seeds := []string{
		"POST:\n  - https://example.test/a",
		"GET:\n  - address: https://example.test/hook\n    authType: token\n    authHeaderName: X-Api-Key",
		"not: [valid, yaml, {",
		"",
		"123",
		"FETCH:\n  - https://example.test/a",
		`{"POST":[{"address":"https://example.test/hook"}]}`,
		`{"2":[{"address":"https://example.test/hook","authType":"basic"}]}`,
		`{malformed json`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, doc string) {
		var fromYAML webhook.WebHooks
		_ = yaml.Unmarshal([]byte(doc), &fromYAML)

		var fromJSON webhook.WebHooks
		_ = json.Unmarshal([]byte(doc), &fromJSON)

		var wh webhook.WebHook
		_ = yaml.Unmarshal([]byte(doc), &wh)

		var wh2 webhook.WebHook
		_ = json.Unmarshal([]byte(doc), &wh2)
	})
}
