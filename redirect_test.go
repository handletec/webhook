package webhook_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/handletec/webhook"
)

// This file replaces the PREVIOUS redirect_test.go, which pinned down the
// OLD, now-superseded behavior inherited from net/http's default redirect
// policy via github.com/svicknesh/httpclient v1.6.0 (Authorization could be
// forwarded on same-host redirects, including an HTTPS->HTTP downgrade, and
// custom auth headers were never stripped on any redirect). That premise is
// now false.
//
// As of github.com/svicknesh/httpclient v1.7.1, SendContext
// (webhook.go) calls client.DisableRedirects() on the fresh, per-call
// *httpclient.Request before every dispatch -- unconditionally, for every
// hook, regardless of AuthType. DisableRedirects installs a CheckRedirect
// policy that always returns http.ErrUseLastResponse, so a 3xx response is
// returned to SendContext as an ordinary Response instead of being
// followed; the redirect destination is never dialed at all. The existing
// success-range/status-code check then classifies that 3xx exactly like any
// other non-2xx status, producing the existing *DeliveryError type -- no new
// redirect-specific error type was introduced.
//
// The property under test throughout this file is that the redirect
// destination NEVER RECEIVES A REQUEST AT ALL, proven by a request counter
// on the target handler -- not that some particular header happens to be
// stripped or absent on arrival. This library no longer relies on net/http's
// header-stripping heuristics for any auth type or origin relationship.

// redirectStatuses covers every 3xx status explicitly called out by the
// task: 301, 302, 303, 307, 308.
var redirectStatuses = []int{
	http.StatusMovedPermanently,  // 301
	http.StatusFound,             // 302
	http.StatusSeeOther,          // 303
	http.StatusTemporaryRedirect, // 307
	http.StatusPermanentRedirect, // 308
}

// noTLS is passed as the tlsConfig argument to SendContext for the
// plain-HTTP httptest servers used throughout this file; it is never
// actually used for a TLS handshake since these origins are non-TLS.
var noTLS = &tls.Config{} //nolint:gosec -- unused for plain-HTTP test servers

// newCountingTarget starts an httptest server that must never receive a
// request in these tests. hit reports whether it ever did, and lastAuth /
// lastToken return whatever it observed on its Authorization / X-Api-Key
// headers, respectively (expected to be empty in every case here, since the
// handler should never even run).
func newCountingTarget(t *testing.T) (addr string, hit func() bool, lastAuth func() string, lastToken func() string) {
	t.Helper()
	var count atomic.Int32
	var mu atomicStrings
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		mu.setAuth(r.Header.Get("Authorization"))
		mu.setToken(r.Header.Get("X-Api-Key"))
		w.WriteHeader(http.StatusOK)
	})
	return srv.URL,
		func() bool { return count.Load() > 0 },
		mu.getAuth,
		mu.getToken
}

// atomicStrings is a tiny mutex-free-enough helper for the two header
// values newCountingTarget's handler might record; the handler is expected
// to run zero times in every test in this file, but the values are captured
// safely regardless in case a regression makes it run.
type atomicStrings struct {
	auth  atomic.Value
	token atomic.Value
}

func (a *atomicStrings) setAuth(v string)  { a.auth.Store(v) }
func (a *atomicStrings) setToken(v string) { a.token.Store(v) }
func (a *atomicStrings) getAuth() string {
	v, _ := a.auth.Load().(string)
	return v
}
func (a *atomicStrings) getToken() string {
	v, _ := a.token.Load().(string)
	return v
}

// newRedirectOrigin starts an httptest server that redirects every request
// to targetAddr+"/target" using the given status code, and counts how many
// requests it itself received.
func newRedirectOrigin(t *testing.T, status int, targetAddr string) (addr string, hits func() int32) {
	t.Helper()
	var count atomic.Int32
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		http.Redirect(w, r, targetAddr+"/target", status)
	})
	return srv.URL, func() int32 { return count.Load() }
}

// asDeliveryError is a small helper shared by every test in this file: it
// requires err to unwrap to *webhook.DeliveryError and returns it, failing
// the test otherwise.
func asDeliveryError(t *testing.T, err error) *webhook.DeliveryError {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var delErr *webhook.DeliveryError
	if !errors.As(err, &delErr) {
		t.Fatalf("expected *webhook.DeliveryError, got %T: %v", err, err)
	}
	return delErr
}

// 1. Unauthenticated hook: origin returns a redirect; redirect target gets
// zero requests; Send returns a DeliveryError; the error/status reflects
// the original 3xx.
func TestRedirect_Unauthenticated_NeverFollowed(t *testing.T) {
	for _, status := range redirectStatuses {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			targetAddr, targetHit, _, _ := newCountingTarget(t)
			originAddr, originHits := newRedirectOrigin(t, status, targetAddr)

			wh, err := webhook.NewWebHook(webhook.MethodGet, originAddr, webhook.WithNoAuth())
			if err != nil {
				t.Fatalf("NewWebHook: %v", err)
			}

			err = wh.SendContext(context.Background(), noTLS, nil, nil, nil)
			delErr := asDeliveryError(t, err)

			if delErr.StatusCode != status {
				t.Errorf("DeliveryError.StatusCode = %d, want %d", delErr.StatusCode, status)
			}
			if targetHit() {
				t.Error("redirect target received a request -- redirects must never be followed")
			}
			if got := originHits(); got != 1 {
				t.Errorf("origin received %d requests, want exactly 1", got)
			}
		})
	}
}

// 2. Basic auth: redirect target gets zero requests, therefore zero
// Authorization headers of any kind.
func TestRedirect_BasicAuth_NeverFollowed(t *testing.T) {
	for _, status := range redirectStatuses {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			targetAddr, targetHit, targetAuth, _ := newCountingTarget(t)
			originAddr, originHits := newRedirectOrigin(t, status, targetAddr)

			wh, err := webhook.NewWebHook(webhook.MethodGet, originAddr, webhook.WithBasicAuth("hello", "world"))
			if err != nil {
				t.Fatalf("NewWebHook: %v", err)
			}

			err = wh.SendContext(context.Background(), noTLS, nil, nil, nil)
			delErr := asDeliveryError(t, err)

			if delErr.StatusCode != status {
				t.Errorf("DeliveryError.StatusCode = %d, want %d", delErr.StatusCode, status)
			}
			if targetHit() {
				t.Error("redirect target received a request -- Basic auth credential must never reach it")
			}
			if got := targetAuth(); got != "" {
				t.Errorf("redirect target observed Authorization %q, want empty (target must never be contacted)", got)
			}
			if got := originHits(); got != 1 {
				t.Errorf("origin received %d requests, want exactly 1", got)
			}
		})
	}
}

// 3. Bearer auth: redirect target gets zero requests; bearer token never
// reaches it.
func TestRedirect_BearerAuth_NeverFollowed(t *testing.T) {
	const bearerToken = "redirect-bearer-secret-token"
	for _, status := range redirectStatuses {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			targetAddr, targetHit, targetAuth, _ := newCountingTarget(t)
			originAddr, originHits := newRedirectOrigin(t, status, targetAddr)

			wh, err := webhook.NewWebHook(webhook.MethodGet, originAddr, webhook.WithBearerToken(bearerToken))
			if err != nil {
				t.Fatalf("NewWebHook: %v", err)
			}

			err = wh.SendContext(context.Background(), noTLS, nil, nil, nil)
			delErr := asDeliveryError(t, err)

			if delErr.StatusCode != status {
				t.Errorf("DeliveryError.StatusCode = %d, want %d", delErr.StatusCode, status)
			}
			if targetHit() {
				t.Error("redirect target received a request -- Bearer token must never reach it")
			}
			if got := targetAuth(); got != "" {
				t.Errorf("redirect target observed Authorization %q, want empty (target must never be contacted)", got)
			}
			if got := originHits(); got != 1 {
				t.Errorf("origin received %d requests, want exactly 1", got)
			}
		})
	}
}

// 4. Custom-token auth (X-Api-Key style custom header): redirect target
// gets zero requests; custom secret never reaches it.
func TestRedirect_CustomToken_NeverFollowed(t *testing.T) {
	const customSecret = "redirect-custom-secret-value"
	for _, status := range redirectStatuses {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			targetAddr, targetHit, _, targetToken := newCountingTarget(t)
			originAddr, originHits := newRedirectOrigin(t, status, targetAddr)

			wh, err := webhook.NewWebHook(webhook.MethodGet, originAddr, webhook.WithToken("X-Api-Key", customSecret))
			if err != nil {
				t.Fatalf("NewWebHook: %v", err)
			}

			err = wh.SendContext(context.Background(), noTLS, nil, nil, nil)
			delErr := asDeliveryError(t, err)

			if delErr.StatusCode != status {
				t.Errorf("DeliveryError.StatusCode = %d, want %d", delErr.StatusCode, status)
			}
			if targetHit() {
				t.Error("redirect target received a request -- custom token must never reach it")
			}
			if got := targetToken(); got != "" {
				t.Errorf("redirect target observed X-Api-Key %q, want empty (target must never be contacted)", got)
			}
			if got := originHits(); got != 1 {
				t.Errorf("origin received %d requests, want exactly 1", got)
			}
		})
	}
}

// TestRedirect_CustomSuccessRangeAccepts3xx proves WithSuccessRange
// semantics are preserved exactly as-is: a caller who explicitly widens the
// success range to include 3xx still gets a successful delivery, even
// though the redirect itself is never followed and the target is never
// contacted.
func TestRedirect_CustomSuccessRangeAccepts3xx(t *testing.T) {
	targetAddr, targetHit, _, _ := newCountingTarget(t)
	originAddr, originHits := newRedirectOrigin(t, http.StatusFound, targetAddr)

	wh, err := webhook.NewWebHook(webhook.MethodGet, originAddr, combine(
		webhook.WithNoAuth(),
		webhook.WithSuccessRange(200, 399),
	))
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	if err := wh.SendContext(context.Background(), noTLS, nil, nil, nil); err != nil {
		t.Fatalf("SendContext: %v, want success -- WithSuccessRange(200,399) must still accept a 3xx status even though it is never followed", err)
	}
	if targetHit() {
		t.Error("redirect target received a request even though delivery counted as success under the custom range")
	}
	if got := originHits(); got != 1 {
		t.Errorf("origin received %d requests, want exactly 1", got)
	}
}

// TestRedirect_DeliveryErrorRedactsSecrets is regression coverage for the
// existing redaction discipline (see errors.go's redactURL / README's
// Security Notes) applied to the new 3xx-rejected case specifically: the
// resulting DeliveryError must expose only scheme://host[:port], never the
// original URL's path/query or the bound secret value.
func TestRedirect_DeliveryErrorRedactsSecrets(t *testing.T) {
	const secretToken = "super-secret-bearer-token-redirect-case"
	targetAddr, targetHit, _, _ := newCountingTarget(t)
	originAddr, _ := newRedirectOrigin(t, http.StatusFound, targetAddr)

	wh, err := webhook.NewWebHook(webhook.MethodGet, originAddr+"/original/path?apikey=dont-leak", webhook.WithBearerToken(secretToken))
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	err = wh.SendContext(context.Background(), noTLS, nil, nil, nil)
	delErr := asDeliveryError(t, err)

	msg := err.Error()
	if strings.Contains(msg, secretToken) {
		t.Errorf("DeliveryError leaked the bearer token: %v", err)
	}
	if strings.Contains(msg, "apikey") || strings.Contains(msg, "dont-leak") {
		t.Errorf("DeliveryError leaked query string content: %v", err)
	}
	if strings.Contains(msg, "/original/path") {
		t.Errorf("DeliveryError leaked the URL path: %v", err)
	}
	if delErr.Target != originAddr {
		t.Errorf("DeliveryError.Target = %q, want %q (scheme://host[:port] only)", delErr.Target, originAddr)
	}
	if targetHit() {
		t.Error("redirect target received a request")
	}
}

// TestRedirect_RetryOn3xx_RetriesConfiguredURLOnly documents and proves the
// retry interaction: a caller may explicitly configure a 3xx status in
// RetryOn (construction does not reject it -- no existing validation
// semantics require that), and each retry attempt re-dispatches only to the
// configured origin URL, never to the redirect Location. Attempt limits are
// still respected.
func TestRedirect_RetryOn3xx_RetriesConfiguredURLOnly(t *testing.T) {
	targetAddr, targetHit, _, _ := newCountingTarget(t)
	originAddr, originHits := newRedirectOrigin(t, http.StatusFound, targetAddr)

	wh, err := webhook.NewWebHook(webhook.MethodGet, originAddr, combine(
		webhook.WithNoAuth(),
		webhook.WithRetry(webhook.RetryPolicy{
			MaxAttempts: 3,
			BaseDelay:   time.Millisecond,
			MaxDelay:    time.Millisecond,
			Multiplier:  1,
			RetryOn:     []int{http.StatusFound},
		}),
	))
	if err != nil {
		t.Fatalf("NewWebHook (explicit 3xx in RetryOn must not be rejected): %v", err)
	}

	err = wh.SendContext(context.Background(), noTLS, nil, nil, nil)
	delErr := asDeliveryError(t, err)

	if delErr.StatusCode != http.StatusFound {
		t.Errorf("DeliveryError.StatusCode = %d, want %d", delErr.StatusCode, http.StatusFound)
	}
	if got := originHits(); got != 3 {
		t.Errorf("origin received %d requests, want exactly 3 (MaxAttempts honored, all against the configured origin)", got)
	}
	if targetHit() {
		t.Error("redirect target received a request across retries -- must stay at 0 on every attempt")
	}
}
