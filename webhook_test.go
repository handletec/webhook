package webhook_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/handletec/webhook"
)

func TestSendContext_MethodCoverage(t *testing.T) {
	cases := []struct {
		name   string
		method webhook.Method
	}{
		{"GET", webhook.MethodGet},
		{"POST", webhook.MethodPost},
		{"PUT", webhook.MethodPut},
		{"PATCH", webhook.MethodPatch},
		{"DELETE", webhook.MethodDelete},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotMethod string
			srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
				gotMethod = r.Method
				w.WriteHeader(http.StatusOK)
			})

			wh, err := webhook.NewWebHook(tc.method, srv.URL, webhook.WithNoAuth())
			if err != nil {
				t.Fatalf("NewWebHook: %v", err)
			}

			err = wh.SendContext(context.Background(), tlsConfig, []byte(`{"a":"b"}`), nil, nil)
			if err != nil {
				t.Fatalf("SendContext: %v", err)
			}
			if gotMethod != tc.name {
				t.Errorf("server saw method %q, want %q", gotMethod, tc.name)
			}
		})
	}
}

func TestSendContext_URLNotDoubled(t *testing.T) {
	// Regression test for the confirmed URL-doubling bug: the full URL was
	// previously passed as both the base (to httpclient.NewRequest) and
	// the endpoint (to Custom), which httpclient concatenates, mangling
	// every outbound path.
	var gotPath, gotRawQuery string
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotRawQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL+"/hooks/incoming", webhook.WithNoAuth())
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	q := webhook.NewQueryPairs("foo", "bar")
	if err := wh.SendContext(context.Background(), tlsConfig, nil, q, nil); err != nil {
		t.Fatalf("SendContext: %v", err)
	}

	if gotPath != "/hooks/incoming" {
		t.Errorf("server saw path %q, want %q (doubled path indicates the URL-doubling bug regressed)", gotPath, "/hooks/incoming")
	}
	if gotRawQuery != "foo=bar" {
		t.Errorf("server saw query %q, want %q", gotRawQuery, "foo=bar")
	}
}

func TestSendContext_StatusRange(t *testing.T) {
	t.Run("default 2xx success", func(t *testing.T) {
		srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, webhook.WithNoAuth())
		if err != nil {
			t.Fatalf("NewWebHook: %v", err)
		}
		if err := wh.SendContext(context.Background(), tlsConfig, nil, nil, nil); err != nil {
			t.Fatalf("expected success, got %v", err)
		}
	})

	t.Run("default 2xx failure surfaces DeliveryError", func(t *testing.T) {
		srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, webhook.WithNoAuth())
		if err != nil {
			t.Fatalf("NewWebHook: %v", err)
		}
		err = wh.SendContext(context.Background(), tlsConfig, nil, nil, nil)
		var de *webhook.DeliveryError
		if !errors.As(err, &de) {
			t.Fatalf("expected *DeliveryError, got %v (%T)", err, err)
		}
		if de.StatusCode != http.StatusInternalServerError {
			t.Errorf("got status %d, want %d", de.StatusCode, http.StatusInternalServerError)
		}
	})

	t.Run("WithSuccessRange override accepts non-2xx", func(t *testing.T) {
		srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, combine(webhook.WithNoAuth(), webhook.WithSuccessRange(200, 499)))
		if err != nil {
			t.Fatalf("NewWebHook: %v", err)
		}
		if err := wh.SendContext(context.Background(), tlsConfig, nil, nil, nil); err != nil {
			t.Fatalf("expected success under overridden range, got %v", err)
		}
	})

	t.Run("WithSuccessRange rejects invalid range", func(t *testing.T) {
		if _, err := webhook.NewWebHook(webhook.MethodGet, "https://example.test", combine(webhook.WithNoAuth(), webhook.WithSuccessRange(500, 200))); err == nil {
			t.Fatal("expected error for min > max")
		}
		if _, err := webhook.NewWebHook(webhook.MethodGet, "https://example.test", combine(webhook.WithNoAuth(), webhook.WithSuccessRange(0, 999))); err == nil {
			t.Fatal("expected error for out-of-range bounds")
		}
	})
}

func TestSendContext_Timeout(t *testing.T) {
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, combine(webhook.WithNoAuth(), webhook.WithTimeout(20*time.Millisecond)))
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	start := time.Now()
	err = wh.SendContext(context.Background(), tlsConfig, nil, nil, nil)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed > 150*time.Millisecond {
		t.Errorf("SendContext took %v, expected it to time out well before the 200ms handler delay", elapsed)
	}
}

func TestWithTimeout_RejectsNonPositive(t *testing.T) {
	if _, err := webhook.NewWebHook(webhook.MethodGet, "https://example.test", combine(webhook.WithNoAuth(), webhook.WithTimeout(0))); err == nil {
		t.Fatal("expected error for zero timeout")
	}
	if _, err := webhook.NewWebHook(webhook.MethodGet, "https://example.test", combine(webhook.WithNoAuth(), webhook.WithTimeout(-1*time.Second))); err == nil {
		t.Fatal("expected error for negative timeout")
	}
}

func TestSendContext_ContextCancellation(t *testing.T) {
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, webhook.WithNoAuth())
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately, before dispatch

	err = wh.SendContext(ctx, tlsConfig, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected errors.Is(err, context.Canceled) to hold through DeliveryError.Unwrap, got %v", err)
	}
}

func TestSendContext_ContextDeadline(t *testing.T) {
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, webhook.WithNoAuth())
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err = wh.SendContext(ctx, tlsConfig, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error for context deadline, got nil")
	}
}

func TestSendContext_EmptyBodyRulesForBodyMethods(t *testing.T) {
	for _, m := range []webhook.Method{webhook.MethodPost, webhook.MethodPut, webhook.MethodPatch} {
		t.Run(m.String(), func(t *testing.T) {
			srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			wh, err := webhook.NewWebHook(m, srv.URL, webhook.WithNoAuth())
			if err != nil {
				t.Fatalf("NewWebHook: %v", err)
			}
			if err := wh.SendContext(context.Background(), tlsConfig, nil, nil, nil); err == nil {
				t.Fatalf("expected error for empty body on method %s, got nil", m)
			}
		})
	}
}

func TestSend_EquivalentToSendContextBackground(t *testing.T) {
	var gotMethod string
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, webhook.WithNoAuth())
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	if err := wh.Send(tlsConfig, nil, nil, nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if gotMethod != "GET" {
		t.Errorf("server saw method %q, want GET", gotMethod)
	}
}

func TestSendContext_DisabledHookIsNoop(t *testing.T) {
	called := false
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, webhook.WithNoAuth())
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}
	wh.Enabled = false

	if err := wh.SendContext(context.Background(), tlsConfig, nil, nil, nil); err != nil {
		t.Fatalf("expected nil error for disabled hook, got %v", err)
	}
	if called {
		t.Error("server should not have been called for a disabled hook")
	}
}
