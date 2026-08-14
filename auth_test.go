package webhook_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/handletec/webhook"
	"gopkg.in/yaml.v3"
)

// TestAuthIsolationMatrix proves that hooks with different auth
// configurations, broadcast together, never leak credentials or headers
// into each other.
func TestAuthIsolationMatrix(t *testing.T) {
	type seen struct {
		auth   string
		token1 string
		token2 string
	}
	var mu sync.Mutex
	got := map[string]seen{}

	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Broadcast fans out to 5 hooks concurrently, so the httptest
		// server dispatches up to 5 concurrent handler invocations --
		// mu protects the shared map from concurrent writes.
		mu.Lock()
		got[r.URL.Path] = seen{
			auth:   r.Header.Get("Authorization"),
			token1: r.Header.Get("X-Api-Key-1"),
			token2: r.Header.Get("X-Api-Key-2"),
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	whs := webhook.NewWebHooks()
	mustAdd := func(method webhook.Method, path string, opt webhook.HookOpt) {
		t.Helper()
		if err := whs.Add(method, srv.URL+path, opt); err != nil {
			t.Fatalf("Add(%s): %v", path, err)
		}
	}

	mustAdd(webhook.MethodGet, "/none", webhook.WithNoAuth())
	mustAdd(webhook.MethodGet, "/basic", webhook.WithBasicAuth("hello", "world"))
	mustAdd(webhook.MethodGet, "/bearer", webhook.WithBearerToken("bearer-secret"))
	mustAdd(webhook.MethodGet, "/token1", webhook.WithToken("X-Api-Key-1", "secret-1"))
	mustAdd(webhook.MethodGet, "/token2", webhook.WithToken("X-Api-Key-2", "secret-2"))

	if err := whs.Broadcast(tlsConfig); err != nil {
		t.Fatalf("Broadcast: %v", err)
	}

	// Take a locked snapshot rather than reading the shared map
	// unprotected: the httptest server's handler goroutines are separate
	// from the goroutines errgroup/Broadcast joins, so there's no
	// synchronization primitive the race detector recognizes between
	// "Broadcast returned" and "the handler's last map write" without one.
	mu.Lock()
	snapshot := make(map[string]seen, len(got))
	for k, v := range got {
		snapshot[k] = v
	}
	mu.Unlock()

	if snapshot["/none"].auth != "" {
		t.Errorf("none hook: got Authorization %q, want empty", snapshot["/none"].auth)
	}
	if !strings.HasPrefix(snapshot["/basic"].auth, "Basic ") {
		t.Errorf("basic hook: got Authorization %q, want a %q-prefixed value", snapshot["/basic"].auth, "Basic ")
	}
	if snapshot["/bearer"].auth != "Bearer bearer-secret" {
		t.Errorf("bearer hook: got Authorization %q, want %q", snapshot["/bearer"].auth, "Bearer bearer-secret")
	}
	// Token-auth hooks must never receive Authorization at all.
	if snapshot["/token1"].auth != "" || snapshot["/token2"].auth != "" {
		t.Errorf("token hooks leaked Authorization: token1=%q token2=%q", snapshot["/token1"].auth, snapshot["/token2"].auth)
	}
	// Each token hook must only see its own custom header, never the other's.
	if snapshot["/token1"].token1 != "secret-1" {
		t.Errorf("token1 hook: got X-Api-Key-1 %q, want secret-1", snapshot["/token1"].token1)
	}
	if snapshot["/token1"].token2 != "" {
		t.Errorf("token1 hook unexpectedly saw X-Api-Key-2 %q", snapshot["/token1"].token2)
	}
	if snapshot["/token2"].token2 != "secret-2" {
		t.Errorf("token2 hook: got X-Api-Key-2 %q, want secret-2", snapshot["/token2"].token2)
	}
	if snapshot["/token2"].token1 != "" {
		t.Errorf("token2 hook unexpectedly saw X-Api-Key-1 %q", snapshot["/token2"].token1)
	}
}

// TestCallerAuthorizationHeaderDoesNotLeak proves a caller-supplied
// Authorization header never reaches a hook whose own auth isn't
// Basic/Bearer (i.e. None or Token).
func TestCallerAuthorizationHeaderDoesNotLeak(t *testing.T) {
	var gotAuth, gotToken string
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotToken = r.Header.Get("X-Api-Key")
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, webhook.WithToken("X-Api-Key", "secret"))
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	callerHeaders := webhook.NewHeaders()
	callerHeaders.Set("Authorization", "Bearer attacker-supplied-value")

	if err := wh.SendContext(context.Background(), tlsConfig, nil, nil, callerHeaders); err != nil {
		t.Fatalf("SendContext: %v", err)
	}

	if gotAuth != "" {
		t.Errorf("caller-supplied Authorization leaked through: %q", gotAuth)
	}
	if gotToken != "secret" {
		t.Errorf("got X-Api-Key %q, want secret", gotToken)
	}
}

// TestPerHookAuthWinsOverCallerHeaders proves a hook's own compiled
// credential always overrides a caller-supplied header of the same name.
func TestPerHookAuthWinsOverCallerHeaders(t *testing.T) {
	var gotAuth string
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, webhook.WithBasicAuth("hello", "world"))
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	callerHeaders := webhook.NewHeaders()
	callerHeaders.Set("Authorization", "this-should-be-overridden")

	if err := wh.SendContext(context.Background(), tlsConfig, nil, nil, callerHeaders); err != nil {
		t.Fatalf("SendContext: %v", err)
	}

	if gotAuth == "" || gotAuth == "this-should-be-overridden" {
		t.Errorf("per-hook Basic auth did not win: got Authorization %q", gotAuth)
	}
}

// TestFailClosed_UnboundAuthRejectsDelivery proves decision #1: a hook that
// declares an AuthType but has no bound credential fails closed at
// SendContext -- the request never leaves.
func TestFailClosed_UnboundAuthRejectsDelivery(t *testing.T) {
	called := false
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	// Construct via YAML (deferred binding path) rather than NewWebHook,
	// since NewWebHook's own With*Auth options always bind the secret
	// immediately.
	var wh webhook.WebHook
	data := []byte(`
address: ` + srv.URL + `
authType: basic
`)
	if err := yaml.Unmarshal(data, &wh); err != nil {
		t.Fatalf("yaml.Unmarshal (config parse must succeed without a secret): %v", err)
	}

	err := wh.SendContext(context.Background(), tlsConfig, nil, nil, nil)
	var de *webhook.DeliveryError
	if !errors.As(err, &de) {
		t.Fatalf("expected *DeliveryError for unbound auth, got %v (%T)", err, err)
	}
	if called {
		t.Error("server was called despite unbound auth -- fail-closed did not hold")
	}
}

// TestValidateAuthConfigVsAuthReady_SeparateGates proves validateAuthConfig
// (structural, parse-time) and authReady (secret-presence, send-time) are
// genuinely separate: a config with a declared-but-unbound auth type
// parses cleanly, and only fails once delivery (or ApplyAuth) is
// attempted.
func TestValidateAuthConfigVsAuthReady_SeparateGates(t *testing.T) {
	var wh webhook.WebHook
	data := []byte(`
address: https://example.test/hook
authType: bearer
`)
	// Structural gate: must succeed even though no token is present.
	if err := yaml.Unmarshal(data, &wh); err != nil {
		t.Fatalf("validateAuthConfig gate: config with unbound auth should parse cleanly, got %v", err)
	}

	// Readiness gate via ApplyAuth: binder that does nothing leaves the
	// hook unready, and ApplyAuth must surface that.
	whs := webhook.NewWebHooks()
	whs[webhook.MethodPost] = []*webhook.WebHook{&wh}
	wh.Method = webhook.MethodPost
	wh.Enabled = true

	if err := whs.ApplyAuth(func(h *webhook.WebHook) error { return nil }); err == nil {
		t.Fatal("expected ApplyAuth to surface authReady failure for unbound bearer auth")
	}

	// Now bind it via the binder and confirm ApplyAuth succeeds and
	// delivery works.
	if err := whs.ApplyAuth(func(h *webhook.WebHook) error {
		h.SetBearerToken("now-bound")
		return nil
	}); err != nil {
		t.Fatalf("ApplyAuth after binding: %v", err)
	}

	var gotAuth string
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	wh.Address = srv.URL

	if err := wh.SendContext(context.Background(), tlsConfig, []byte(`{}`), nil, nil); err != nil {
		t.Fatalf("SendContext after ApplyAuth binding: %v", err)
	}
	if gotAuth != "Bearer now-bound" {
		t.Errorf("got Authorization %q, want %q", gotAuth, "Bearer now-bound")
	}
}
