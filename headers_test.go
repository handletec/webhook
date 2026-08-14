package webhook_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/handletec/webhook"
)

func TestHeaders_InvalidNameRejected(t *testing.T) {
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, webhook.WithNoAuth())
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	headers := webhook.NewHeaders()
	// A space and a colon are not valid RFC 7230 tchars for a header
	// field name; Headers.Set/http.CanonicalHeaderKey do not themselves
	// reject this, so it must be caught by validateOutboundHeaders at
	// dispatch time.
	headers.Set("Bad Header:Name", "value")

	if err := wh.SendContext(context.Background(), tlsConfig, nil, nil, headers); err == nil {
		t.Fatal("expected error for invalid header name, got nil")
	}
}

func TestHeaders_InvalidValueRejected(t *testing.T) {
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, webhook.WithNoAuth())
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	headers := webhook.NewHeaders()
	headers.Set("X-Custom", "value-with-\r\ninjected-header: evil")

	if err := wh.SendContext(context.Background(), tlsConfig, nil, nil, headers); err == nil {
		t.Fatal("expected error for CR/LF in header value, got nil")
	}
}

func TestHeaders_ValidHeadersPassThrough(t *testing.T) {
	var got string
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, webhook.WithNoAuth())
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	headers := webhook.NewHeaders()
	headers.Set("X-Custom", "valid-value")

	if err := wh.SendContext(context.Background(), tlsConfig, nil, nil, headers); err != nil {
		t.Fatalf("SendContext: %v", err)
	}
	if got != "valid-value" {
		t.Errorf("got X-Custom=%q, want valid-value", got)
	}
}
