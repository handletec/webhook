package webhook_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/handletec/webhook"
)

func TestQuery_PrecedenceURLThenWithQueryThenJSON(t *testing.T) {
	var gotQuery url.Values
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL+"?key=from-url", webhook.WithNoAuth())
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	q := webhook.NewQueryPairs("key", "from-with-query")
	body := []byte(`{"key":"from-json"}`)

	if err := wh.SendContext(context.Background(), tlsConfig, body, q, nil); err != nil {
		t.Fatalf("SendContext: %v", err)
	}

	if got := gotQuery.Get("key"); got != "from-json" {
		t.Errorf("got key=%q, want %q (URL query -> WithQuery -> JSON-flattened; JSON wins)", got, "from-json")
	}
}

func TestQuery_WithQueryAddsToURLQuery(t *testing.T) {
	var gotQuery url.Values
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL+"?a=1", webhook.WithNoAuth())
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	q := webhook.NewQueryPairs("b", "2")
	if err := wh.SendContext(context.Background(), tlsConfig, nil, q, nil); err != nil {
		t.Fatalf("SendContext: %v", err)
	}

	if gotQuery.Get("a") != "1" || gotQuery.Get("b") != "2" {
		t.Errorf("got query %v, want a=1 and b=2 both present", gotQuery)
	}
}

// TestQuery_WithQueryOverwritesURLQueryOnCollision isolates just the
// address-own-query vs. WithQuery pair (no JSON-flatten stage involved),
// asserting WithQuery wins on a colliding key -- last-write-wins,
// consistent with how the JSON-flatten stage already behaves. Regression
// test for a merge that previously used q.Add (append) instead of
// overwrite for this stage, which meant url.Values.Get (which returns the
// *first* value) resolved to the address's own value instead of
// WithQuery's, contradicting the documented precedence.
func TestQuery_WithQueryOverwritesURLQueryOnCollision(t *testing.T) {
	var gotQuery url.Values
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL+"?key=from-url", webhook.WithNoAuth())
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	q := webhook.NewQueryPairs("key", "from-with-query")
	if err := wh.SendContext(context.Background(), tlsConfig, nil, q, nil); err != nil {
		t.Fatalf("SendContext: %v", err)
	}

	if got := gotQuery.Get("key"); got != "from-with-query" {
		t.Errorf("got key=%q, want %q (WithQuery must overwrite a colliding address-own-query value, not just append to it)", got, "from-with-query")
	}
	if got := gotQuery["key"]; len(got) != 1 {
		t.Errorf("got %d values for key %q, want exactly 1 (overwrite, not append): %v", len(got), "key", got)
	}
}

func TestQuery_InvalidJSONForGETReturnsError(t *testing.T) {
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, webhook.WithNoAuth())
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	err = wh.SendContext(context.Background(), tlsConfig, []byte("{not valid json"), nil, nil)
	if err == nil {
		t.Fatal("expected an error for invalid JSON payload on a GET request, got nil")
	}
}

func TestQuery_FlattenTypes(t *testing.T) {
	var gotQuery url.Values
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, webhook.WithNoAuth())
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	body := []byte(`{
		"str": "hello",
		"num": 42,
		"flag": true,
		"nothing": null,
		"list": ["a", "b", "c"],
		"nested": {"x": 1, "y": "z"}
	}`)

	if err := wh.SendContext(context.Background(), tlsConfig, body, nil, nil); err != nil {
		t.Fatalf("SendContext: %v", err)
	}

	if gotQuery.Get("str") != "hello" {
		t.Errorf("str: got %q, want hello", gotQuery.Get("str"))
	}
	if gotQuery.Get("num") != "42" {
		t.Errorf("num: got %q, want 42", gotQuery.Get("num"))
	}
	if gotQuery.Get("flag") != "true" {
		t.Errorf("flag: got %q, want true", gotQuery.Get("flag"))
	}
	if _, present := gotQuery["nothing"]; present {
		t.Errorf("nothing: expected a null value to be skipped, got present with %q", gotQuery.Get("nothing"))
	}
	if got := gotQuery["list"]; len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("list: got %v, want [a b c]", got)
	}
	if gotQuery.Get("nested") == "" {
		t.Error("nested: expected a JSON-re-encoded value, got empty")
	}
}
