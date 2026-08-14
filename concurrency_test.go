package webhook_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/handletec/webhook"
)

// TestConcurrency_BroadcastConcurrentCalls proves concurrent Broadcast
// calls against the same WebHooks registry are safe (run with -race).
func TestConcurrency_BroadcastConcurrentCalls(t *testing.T) {
	var requests int32
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusOK)
	})

	whs := webhook.NewWebHooks()
	for i := 0; i < 5; i++ {
		if err := whs.Add(webhook.MethodGet, srv.URL+"/"+string(rune('a'+i)), webhook.WithNoAuth()); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = whs.Broadcast(tlsConfig)
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&requests); got != 50 {
		t.Errorf("got %d total requests, want 50 (10 concurrent broadcasts x 5 hooks)", got)
	}
}

// TestConcurrency_SettersRaceWithSendContext proves the single-snapshot
// lock fix: concurrent calls to the supported setters (SetBasicAuth,
// SetBearerToken, SetCustomToken, SetHeader, SetRetry) racing against
// concurrent SendContext calls on the same *WebHook must never deadlock
// and (verified by the -race build) never data-race. Run with -race.
func TestConcurrency_SettersRaceWithSendContext(t *testing.T) {
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodGet, srv.URL, webhook.WithNoAuth())
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = wh.SendContext(context.Background(), tlsConfig, nil, nil, nil)
				}
			}
		}()
	}

	setters := []func(){
		func() { wh.SetBasicAuth("user", "pass") },
		func() { wh.SetBearerToken("token") },
		func() { wh.SetCustomToken("X-Api-Key", "value") },
		func() { wh.SetHeader("X-Trace", "1") },
		func() { _ = wh.SetRetry(webhook.RetryPolicy{}) },
	}
	for _, set := range setters {
		wg.Add(1)
		go func(set func()) {
			defer wg.Done()
			deadline := time.Now().Add(100 * time.Millisecond)
			for time.Now().Before(deadline) {
				set()
			}
		}(set)
	}

	time.Sleep(150 * time.Millisecond)
	close(stop)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent setters/SendContext calls appear to have deadlocked")
	}
}

// TestConcurrency_WithConcurrencyBoundsInFlight proves WithConcurrency
// actually bounds the number of in-flight goroutines during fan-out.
func TestConcurrency_WithConcurrencyBoundsInFlight(t *testing.T) {
	var (
		mu      sync.Mutex
		current int
		peak    int
	)
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		current++
		if current > peak {
			peak = current
		}
		mu.Unlock()

		time.Sleep(30 * time.Millisecond)

		mu.Lock()
		current--
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
	})

	whs := webhook.NewWebHooks()
	for i := 0; i < 10; i++ {
		if err := whs.Add(webhook.MethodGet, srv.URL+"/"+string(rune('a'+i)), webhook.WithNoAuth()); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}

	if err := whs.Broadcast(tlsConfig, webhook.WithConcurrency(3)); err != nil {
		t.Fatalf("Broadcast: %v", err)
	}

	mu.Lock()
	gotPeak := peak
	mu.Unlock()

	if gotPeak > 3 {
		t.Errorf("peak concurrency was %d, want <= 3 (WithConcurrency(3))", gotPeak)
	}
	if gotPeak < 2 {
		t.Errorf("peak concurrency was %d, expected the fan-out to actually run some hooks in parallel", gotPeak)
	}
}

// TestConcurrency_OptionsSnapshotAtConstructionTime proves WithData/
// WithQuery/WithHeaders copy their input the moment they're called, not
// deferred to send time -- mutating the caller's original slice/map after
// the With* call returns must not affect what's actually sent.
func TestConcurrency_OptionsSnapshotAtConstructionTime(t *testing.T) {
	var gotBody []byte
	var gotQuery url.Values
	var gotHeader string
	srv, tlsConfig := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotQuery = r.URL.Query()
		gotHeader = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
	})

	wh, err := webhook.NewWebHook(webhook.MethodPost, srv.URL, webhook.WithNoAuth())
	if err != nil {
		t.Fatalf("NewWebHook: %v", err)
	}
	whs := webhook.NewWebHooks()
	whs[webhook.MethodPost] = []*webhook.WebHook{wh}

	body := []byte(`{"a":"original"}`)
	q := webhook.NewQueryPairs("k", "original")
	headers := webhook.NewHeaders()
	headers.Set("X-Custom", "original")

	dataOpt := webhook.WithData(body)
	queryOpt := webhook.WithQuery(q)
	headersOpt := webhook.WithHeaders(headers)

	// Mutate strictly after each With* call returns -- the copy already
	// happened synchronously inside the call, not raced against it.
	body[2] = 'X'
	q.Set("k", "mutated")
	headers.Set("X-Custom", "mutated")

	if err := whs.Broadcast(tlsConfig, dataOpt, queryOpt, headersOpt); err != nil {
		t.Fatalf("Broadcast: %v", err)
	}

	if string(gotBody) != `{"a":"original"}` {
		t.Errorf("got body %q, want the pre-mutation snapshot %q", gotBody, `{"a":"original"}`)
	}
	if gotQuery.Get("k") != "original" {
		t.Errorf("got query k=%q, want original", gotQuery.Get("k"))
	}
	if gotHeader != "original" {
		t.Errorf("got header X-Custom=%q, want original", gotHeader)
	}
}
