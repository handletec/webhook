package webhook_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/handletec/webhook"
	"gopkg.in/yaml.v3"
)

func TestConfig_WebHook_Defaults(t *testing.T) {
	var wh webhook.WebHook
	if err := yaml.Unmarshal([]byte("https://example.test/hook"), &wh); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	if !wh.Enabled {
		t.Error("expected default Enabled=true")
	}
	if wh.Method != webhook.MethodPost {
		t.Errorf("expected default Method=Post, got %v", wh.Method)
	}
	if wh.AuthType != webhook.AuthTypeNone {
		t.Errorf("expected default AuthType=None, got %v", wh.AuthType)
	}
}

func TestConfig_YAML_ScalarShorthand(t *testing.T) {
	data := []byte(`
POST:
  - https://example.test/a
  - https://example.test/b
`)
	var whs webhook.WebHooks
	if err := yaml.Unmarshal(data, &whs); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	hooks := whs[webhook.MethodPost]
	if len(hooks) != 2 {
		t.Fatalf("got %d hooks, want 2", len(hooks))
	}
	if hooks[0].Address != "https://example.test/a" {
		t.Errorf("got address %q", hooks[0].Address)
	}
	if hooks[0].AuthType != webhook.AuthTypeNone {
		t.Errorf("got authType %v, want AuthTypeNone", hooks[0].AuthType)
	}
	if !hooks[0].Enabled {
		t.Error("expected default Enabled=true")
	}
}

func TestConfig_YAML_MappingForm(t *testing.T) {
	data := []byte(`
POST:
  - address: https://example.test/hook
    authType: token
    authHeaderName: X-Api-Key
    enabled: false
`)
	var whs webhook.WebHooks
	if err := yaml.Unmarshal(data, &whs); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	hooks := whs[webhook.MethodPost]
	if len(hooks) != 1 {
		t.Fatalf("got %d hooks, want 1", len(hooks))
	}
	h := hooks[0]
	if h.Enabled {
		t.Error("expected Enabled=false")
	}
	if h.AuthType != webhook.AuthTypeToken {
		t.Errorf("got authType %v, want AuthTypeToken", h.AuthType)
	}
	if h.AuthHeaderName != "X-Api-Key" {
		t.Errorf("got authHeaderName %q, want X-Api-Key", h.AuthHeaderName)
	}
}

func TestConfig_JSON_Equivalent(t *testing.T) {
	data := []byte(`{"POST":[{"address":"https://example.test/hook","authType":"token","authHeaderName":"X-Api-Key","enabled":false}]}`)
	var whs webhook.WebHooks
	if err := json.Unmarshal(data, &whs); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	hooks := whs[webhook.MethodPost]
	if len(hooks) != 1 {
		t.Fatalf("got %d hooks, want 1", len(hooks))
	}
	h := hooks[0]
	if h.Enabled {
		t.Error("expected Enabled=false")
	}
	if h.AuthType != webhook.AuthTypeToken {
		t.Errorf("got authType %v, want AuthTypeToken", h.AuthType)
	}
	if h.AuthHeaderName != "X-Api-Key" {
		t.Errorf("got authHeaderName %q, want X-Api-Key", h.AuthHeaderName)
	}
}

func TestConfig_RoundTrip_YAML(t *testing.T) {
	original := webhook.NewWebHooks()
	if err := original.Add(webhook.MethodPost, "https://example.test/hook", webhook.WithToken("X-Api-Key", "should-not-appear")); err != nil {
		t.Fatalf("Add: %v", err)
	}

	out, err := yaml.Marshal(original)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}

	var roundtripped webhook.WebHooks
	if err := yaml.Unmarshal(out, &roundtripped); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}

	hooks := roundtripped[webhook.MethodPost]
	if len(hooks) != 1 {
		t.Fatalf("got %d hooks after round-trip, want 1", len(hooks))
	}
	if hooks[0].Address != "https://example.test/hook" {
		t.Errorf("got address %q after round-trip", hooks[0].Address)
	}
	if hooks[0].AuthType != webhook.AuthTypeToken {
		t.Errorf("got authType %v after round-trip, want AuthTypeToken", hooks[0].AuthType)
	}
	if strings.Contains(string(out), "should-not-appear") {
		t.Error("marshaled YAML leaked the secret token value")
	}
}

func TestConfig_RoundTrip_JSON(t *testing.T) {
	original := webhook.NewWebHooks()
	if err := original.Add(webhook.MethodGet, "https://example.test/hook", webhook.WithBasicAuth("user", "super-secret-password")); err != nil {
		t.Fatalf("Add: %v", err)
	}

	out, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var roundtripped webhook.WebHooks
	if err := json.Unmarshal(out, &roundtripped); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	hooks := roundtripped[webhook.MethodGet]
	if len(hooks) != 1 {
		t.Fatalf("got %d hooks after round-trip, want 1", len(hooks))
	}
	if hooks[0].Address != "https://example.test/hook" {
		t.Errorf("got address %q after round-trip", hooks[0].Address)
	}
	if hooks[0].AuthType != webhook.AuthTypeBasic {
		t.Errorf("got authType %v after round-trip, want AuthTypeBasic", hooks[0].AuthType)
	}
	if strings.Contains(string(out), "super-secret-password") {
		t.Error("marshaled JSON leaked the secret password")
	}
	if !strings.Contains(string(out), `"GET"`) {
		t.Errorf("expected canonical method name key %q in output, got %s", "GET", out)
	}
}

func TestConfig_InvalidRejected(t *testing.T) {
	t.Run("invalid method key", func(t *testing.T) {
		data := []byte(`
FETCH:
  - https://example.test/a
`)
		var whs webhook.WebHooks
		if err := yaml.Unmarshal(data, &whs); err == nil {
			t.Fatal("expected error for invalid method key")
		}
	})

	t.Run("invalid auth type", func(t *testing.T) {
		data := []byte(`
address: https://example.test/a
authType: hmac
`)
		var wh webhook.WebHook
		if err := yaml.Unmarshal(data, &wh); err == nil {
			t.Fatal("expected error for invalid authType")
		}
	})

	t.Run("invalid address scheme", func(t *testing.T) {
		data := []byte(`
address: ftp://example.test/a
`)
		var wh webhook.WebHook
		if err := yaml.Unmarshal(data, &wh); err == nil {
			t.Fatal("expected error for non-http(s) scheme")
		}
	})

	t.Run("token auth missing header name", func(t *testing.T) {
		data := []byte(`
address: https://example.test/a
authType: token
`)
		var wh webhook.WebHook
		if err := yaml.Unmarshal(data, &wh); err == nil {
			t.Fatal("expected error for token auth without authHeaderName")
		}
	})
}

func TestConfig_DuplicateAddressesDeduped(t *testing.T) {
	whs := webhook.NewWebHooks()
	if err := whs.Add(webhook.MethodGet, "https://example.test/hook", webhook.WithNoAuth()); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := whs.Add(webhook.MethodGet, "https://EXAMPLE.test/hook", webhook.WithNoAuth()); err != nil {
		t.Fatalf("Add (dup): %v", err)
	}
	if got := len(whs[webhook.MethodGet]); got != 1 {
		t.Errorf("got %d hooks, want 1 (case-insensitive dedup)", got)
	}

	data := []byte(`
GET:
  - https://example.test/hook
  - https://EXAMPLE.test/hook
`)
	var fromYAML webhook.WebHooks
	if err := yaml.Unmarshal(data, &fromYAML); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	if got := len(fromYAML[webhook.MethodGet]); got != 1 {
		t.Errorf("got %d hooks from YAML, want 1 (case-insensitive dedup)", got)
	}
}

func TestConfig_DeferredSecretBindingThenSend(t *testing.T) {
	var gotAuth string
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})

	data := []byte(`
GET:
  - address: ` + srv.URL + `
    authType: bearer
`)
	var whs webhook.WebHooks
	if err := yaml.Unmarshal(data, &whs); err != nil {
		t.Fatalf("yaml.Unmarshal (config without secret must parse cleanly): %v", err)
	}

	if err := whs.ApplyAuth(func(h *webhook.WebHook) error {
		h.SetBearerToken("deferred-secret")
		return nil
	}); err != nil {
		t.Fatalf("ApplyAuth: %v", err)
	}

	if err := whs.Broadcast(tlsConfig); err != nil {
		t.Fatalf("Broadcast: %v", err)
	}
	if gotAuth != "Bearer deferred-secret" {
		t.Errorf("got Authorization %q, want %q", gotAuth, "Bearer deferred-secret")
	}
}

func TestConfig_SecretSafeOutput(t *testing.T) {
	whs := webhook.NewWebHooks()
	if err := whs.Add(webhook.MethodPost, "https://example.test/hook", webhook.WithBasicAuth("user", "top-secret-password")); err != nil {
		t.Fatalf("Add: %v", err)
	}

	yamlOut, err := yaml.Marshal(whs)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	if strings.Contains(string(yamlOut), "top-secret-password") {
		t.Errorf("YAML output leaked the secret: %s", yamlOut)
	}

	jsonOut, err := json.Marshal(whs)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(jsonOut), "top-secret-password") {
		t.Errorf("JSON output leaked the secret: %s", jsonOut)
	}

	hooks := whs[webhook.MethodPost]
	if strings.Contains(hooks[0].String(), "top-secret-password") {
		t.Errorf("WebHook.String() leaked the secret: %s", hooks[0].String())
	}
}

func TestConfig_JSON_MethodKeyBackwardCompat(t *testing.T) {
	// "2" is the legacy raw-integer-string key for MethodPost (see
	// method.go's iota ordering: GET=1, POST=2, PUT=3, PATCH=4, DELETE=5).
	data := []byte(`{"2":[{"address":"https://example.test/hook"}]}`)
	var whs webhook.WebHooks
	if err := json.Unmarshal(data, &whs); err != nil {
		t.Fatalf("json.Unmarshal with legacy integer key: %v", err)
	}
	if len(whs[webhook.MethodPost]) != 1 {
		t.Fatalf("got %d hooks under MethodPost, want 1", len(whs[webhook.MethodPost]))
	}

	data2 := []byte(`{"POST":[{"address":"https://example.test/hook"}]}`)
	var whs2 webhook.WebHooks
	if err := json.Unmarshal(data2, &whs2); err != nil {
		t.Fatalf("json.Unmarshal with named key: %v", err)
	}
	if len(whs2[webhook.MethodPost]) != 1 {
		t.Fatalf("got %d hooks under MethodPost, want 1", len(whs2[webhook.MethodPost]))
	}
}

func TestConfig_JSON_AlwaysEmitsNamedKeys(t *testing.T) {
	whs := webhook.NewWebHooks()
	if err := whs.Add(webhook.MethodPost, "https://example.test/hook", webhook.WithNoAuth()); err != nil {
		t.Fatalf("Add: %v", err)
	}
	out, err := json.Marshal(whs)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !strings.Contains(string(out), `"POST"`) {
		t.Errorf("expected canonical method name key %q in output, got %s", "POST", out)
	}
	if strings.Contains(string(out), `"2"`) {
		t.Errorf("output should not contain the legacy raw-integer key, got %s", out)
	}
}
