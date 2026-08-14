package webhook_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/handletec/webhook"
)

func TestRetry_DisabledByDefault(t *testing.T) {
	var attempts int32
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, webhook.WithNoAuth())
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	_ = wh.SendContext(context.Background(), tlsConfig, nil, nil, nil)
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Errorf("got %d attempts, want exactly 1 (retry must be off by default)", got)
	}
}

func TestRetry_SucceedsAfterTransientFailures(t *testing.T) {
	var attempts int32
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, combine(webhook.WithNoAuth(), webhook.WithRetry(webhook.RetryPolicy{
		MaxAttempts: 5,
		BaseDelay:   1 * time.Millisecond,
		MaxDelay:    5 * time.Millisecond,
		Multiplier:  1,
	})))
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	if err := wh.SendContext(context.Background(), tlsConfig, nil, nil, nil); err != nil {
		t.Fatalf("SendContext: %v", err)
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Errorf("got %d attempts, want exactly 3", got)
	}
}

func TestRetry_AttemptLimitHonored(t *testing.T) {
	var attempts int32
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, combine(webhook.WithNoAuth(), webhook.WithRetry(webhook.RetryPolicy{
		MaxAttempts: 4,
		BaseDelay:   1 * time.Millisecond,
		MaxDelay:    5 * time.Millisecond,
		Multiplier:  1,
	})))
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	err = wh.SendContext(context.Background(), tlsConfig, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if got := atomic.LoadInt32(&attempts); got != 4 {
		t.Errorf("got %d attempts, want exactly 4", got)
	}
}

func TestRetry_PermanentFailureNotRetried(t *testing.T) {
	var attempts int32
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusBadRequest)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, combine(webhook.WithNoAuth(), webhook.WithRetry(webhook.RetryPolicy{
		MaxAttempts: 5,
		BaseDelay:   1 * time.Millisecond,
	})))
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	_ = wh.SendContext(context.Background(), tlsConfig, nil, nil, nil)
	if got := atomic.LoadInt32(&attempts); got != 1 {
		t.Errorf("got %d attempts for a non-retryable status (400), want exactly 1", got)
	}
}

func TestRetry_TransportErrorNotRetried(t *testing.T) {
	// Dial a port nothing is listening on -- a genuine transport-level
	// failure, which httpclient (confirmed by reading its connect(): a
	// transport error returns immediately, "do not retry") never retries
	// regardless of RetryOn/MaxAttempts.
	wh, err := webhook.NewWebHook(webhook.MethodGet, "https://127.0.0.1:1", combine(webhook.WithNoAuth(), webhook.WithRetry(webhook.RetryPolicy{
		MaxAttempts: 5,
		BaseDelay:   1 * time.Millisecond,
	})))
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	start := time.Now()
	err = wh.SendContext(context.Background(), &tls.Config{InsecureSkipVerify: true}, nil, nil, nil) //nolint:gosec -- unreachable test target, no real TLS peer
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a transport-level error")
	}
	// If this had incorrectly retried 5 times with backoff, it would take
	// substantially longer than a single connection failure.
	if elapsed > 2*time.Second {
		t.Errorf("SendContext took %v -- looks like it retried a transport error, which httpclient never does", elapsed)
	}
}

func TestRetry_ContextCancellationStopsRetries(t *testing.T) {
	var attempts int32
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, combine(webhook.WithNoAuth(), webhook.WithRetry(webhook.RetryPolicy{
		MaxAttempts: 10,
		BaseDelay:   50 * time.Millisecond,
		MaxDelay:    50 * time.Millisecond,
		Multiplier:  1,
	})))
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = wh.SendContext(ctx, tlsConfig, nil, nil, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from context cancellation mid-backoff")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("SendContext took %v after a 120ms context timeout -- retries did not stop on cancellation", elapsed)
	}
	if got := atomic.LoadInt32(&attempts); got >= 10 {
		t.Errorf("got %d attempts, expected fewer than the configured MaxAttempts=10 due to cancellation", got)
	}
}

func TestRetry_DelayBoundsRespected(t *testing.T) {
	var attempts int32
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, combine(webhook.WithNoAuth(), webhook.WithRetry(webhook.RetryPolicy{
		MaxAttempts: 5,
		BaseDelay:   10 * time.Millisecond,
		MaxDelay:    10 * time.Millisecond,
		Multiplier:  1,
	})))
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	start := time.Now()
	if err := wh.SendContext(context.Background(), tlsConfig, nil, nil, nil); err != nil {
		t.Fatalf("SendContext: %v", err)
	}
	elapsed := time.Since(start)

	// 2 retries at ~10ms each (constant multiplier=1) = ~20ms minimum;
	// generous upper bound to absorb CI/scheduler jitter.
	if elapsed < 15*time.Millisecond {
		t.Errorf("elapsed %v is suspiciously fast for 2 backoff delays of ~10ms", elapsed)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("elapsed %v is far beyond the expected bounded backoff range", elapsed)
	}
}

func TestRetry_NonIdempotentGuard(t *testing.T) {
	t.Run("WithRetry rejects POST without AllowNonIdempotentRetry", func(t *testing.T) {
		_, err := webhook.NewWebHook(webhook.MethodPost, "https://example.test", combine(webhook.WithNoAuth(), webhook.WithRetry(webhook.RetryPolicy{MaxAttempts: 3})))
		if err == nil {
			t.Fatal("expected construction error")
		}
	})

	t.Run("WithRetry rejects PATCH without AllowNonIdempotentRetry", func(t *testing.T) {
		_, err := webhook.NewWebHook(webhook.MethodPatch, "https://example.test", combine(webhook.WithNoAuth(), webhook.WithRetry(webhook.RetryPolicy{MaxAttempts: 3})))
		if err == nil {
			t.Fatal("expected construction error")
		}
	})

	t.Run("WithRetry succeeds for POST with AllowNonIdempotentRetry", func(t *testing.T) {
		_, err := webhook.NewWebHook(webhook.MethodPost, "https://example.test", combine(webhook.WithNoAuth(), webhook.WithRetry(webhook.RetryPolicy{MaxAttempts: 3, AllowNonIdempotentRetry: true})))
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
	})

	t.Run("SetRetry rejects POST without AllowNonIdempotentRetry", func(t *testing.T) {
		wh, err := webhook.NewWebHook(webhook.MethodPost, "https://example.test", webhook.WithNoAuth())
		if err != nil {
			t.Fatalf("NewWebHook: %v", err)
		}
		if err := wh.SetRetry(webhook.RetryPolicy{MaxAttempts: 3}); err == nil {
			t.Fatal("expected SetRetry to reject non-idempotent retry without the guard")
		}
	})

	t.Run("defense-in-depth: Method changed after SetRetry fails closed at dispatch", func(t *testing.T) {
		// Reproduces the exact sequence from the plan's added requirement
		// (§6d): configure retry while Method is GET, then directly
		// mutate wh.Method to POST, then send -- must fail closed instead
		// of silently retrying a non-idempotent request. WithRetry/
		// SetRetry's own construction-time check cannot catch this,
		// because Method is an exported, directly-writable field for
		// compatibility -- only SendContext's re-check against its own
		// single-snapshot (Method, RetryPolicy) pair can.
		var attempts int32
		srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&attempts, 1)
			w.WriteHeader(http.StatusServiceUnavailable)
		})

		wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, webhook.WithNoAuth())
		if err != nil {
			t.Fatalf("NewWebHook: %v", err)
		}
		if err := wh.SetRetry(webhook.RetryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond}); err != nil {
			t.Fatalf("SetRetry while Method=GET: %v", err)
		}

		// Directly mutate the exported field, bypassing SetRetry's own
		// construction-time check entirely.
		wh.Method = webhook.MethodPost

		err = wh.SendContext(context.Background(), tlsConfig, []byte(`{"a":"b"}`), nil, nil)
		if err == nil {
			t.Fatal("expected SendContext to fail closed for a non-idempotent method with an active retry policy")
		}
		if got := atomic.LoadInt32(&attempts); got != 0 {
			t.Errorf("got %d requests sent to the server, want 0 -- SendContext must fail before any network I/O", got)
		}
	})
}

func TestRetry_ExhaustedErrorHasNoSecretLeakage(t *testing.T) {
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, combine(
		webhook.WithBearerToken("super-secret-bearer-token"),
		webhook.WithRetry(webhook.RetryPolicy{MaxAttempts: 2, BaseDelay: time.Millisecond}),
	))
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	err = wh.SendContext(context.Background(), tlsConfig, nil, nil, nil)
	if err == nil {
		t.Fatal("expected an error after exhausting retries")
	}
	if strings.Contains(err.Error(), "super-secret-bearer-token") {
		t.Errorf("retry-exhausted error leaked the bearer token: %v", err)
	}
}
