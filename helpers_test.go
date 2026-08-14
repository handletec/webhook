package webhook_test

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/handletec/webhook"
)

// canBindLocalListener probes whether this process is permitted to bind a
// local TCP listener. Some sandboxed/agent execution environments deny
// bind() entirely (httptest.NewServer/NewTLSServer panic in that case
// rather than returning an error), so tests that need a real listener
// check this first and skip gracefully instead of crashing the whole test
// binary.
func canBindLocalListener() bool {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// newTLSServer starts an httptest.NewTLSServer with handler and returns a
// tls.Config that trusts the server's ephemeral certificate. The server is
// closed automatically via t.Cleanup. Skips (does not fail) the test when
// this environment does not permit binding a local listener.
func newTLSServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *tls.Config) {
	t.Helper()
	if !canBindLocalListener() {
		t.Skip("skipping: this environment does not permit binding a local TCP listener (network-sandboxed runner) -- run `go test` outside that sandbox to execute this test")
	}
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	// InsecureSkipVerify is safe here: this is a local, ephemeral
	// httptest.Server certificate used only within this test process, not
	// a real network peer.
	tlsConfig := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	return srv, tlsConfig
}

// newServer starts a plain (non-TLS) httptest.Server. Skips (does not
// fail) the test when this environment does not permit binding a local
// listener.
func newServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	if !canBindLocalListener() {
		t.Skip("skipping: this environment does not permit binding a local TCP listener (network-sandboxed runner) -- run `go test` outside that sandbox to execute this test")
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// combine composes multiple HookOpt values into a single HookOpt, since
// NewWebHook accepts exactly one. Used by tests that need to combine e.g.
// an auth option with WithTimeout/WithSuccessRange/WithRetry.
func combine(opts ...webhook.HookOpt) webhook.HookOpt {
	return func(h *webhook.WebHook) error {
		for _, o := range opts {
			if o == nil {
				continue
			}
			if err := o(h); err != nil {
				return err
			}
		}
		return nil
	}
}
