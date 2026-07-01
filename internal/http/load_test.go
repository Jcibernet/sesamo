package http

import (
	"context"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jcibernet/sesamo/internal/session"
)

// TestLoadIntrospect drives concurrent introspection against a live
// session and asserts the latency SLO: p50 < 5ms, p99 < 20ms. It only
// runs when SESAMO_TEST_DB is set and -short is not passed.
//
// This is the single hot path every protected request hits, so it is the
// one number that defines whether Sésamo is "fast enough to not need a
// client SDK or JWT". Run with: go test -run TestLoadIntrospect -v
func TestLoadIntrospect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in -short mode")
	}
	h := newHarness(t)

	// Create a real user + session directly through the stores.
	ctx := context.Background()
	email := uniqueEmail("load")
	h.signup(email, "load-test-pass-1")
	var userID string
	if err := h.pool.QueryRow(ctx, `SELECT id FROM users WHERE email=$1`, email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	store := session.NewStore(h.pool, session.Config{
		Lifetime: 30 * 24 * time.Hour, RollingRenewalThreshold: 15 * time.Minute,
	})
	created, err := store.Create(ctx, session.CreateInput{UserID: userID})
	if err != nil {
		t.Fatal(err)
	}
	token := created.Token

	const (
		workers = 16
		perWork = 200 // 3200 total requests
	)
	lat := make([][]time.Duration, workers)
	var wg sync.WaitGroup

	start := time.Now()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			samples := make([]time.Duration, 0, perWork)
			for i := 0; i < perWork; i++ {
				t0 := time.Now()
				res, body := h.introspect(token)
				samples = append(samples, time.Since(t0))
				// Correctness guard: a fast error must not pass the SLO.
				// Every request hits a live, valid session, so it must
				// return 200 with an active introspection result.
				if res.StatusCode != http.StatusOK {
					t.Errorf("introspect status %d, want 200", res.StatusCode)
					return
				}
				if !strings.Contains(body, `"active":true`) {
					t.Errorf("introspect body not active: %s", body)
					return
				}
			}
			lat[w] = samples
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)

	all := make([]time.Duration, 0, workers*perWork)
	for _, s := range lat {
		all = append(all, s...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })

	p50 := all[len(all)*50/100]
	p95 := all[len(all)*95/100]
	p99 := all[len(all)*99/100]
	rps := float64(len(all)) / elapsed.Seconds()

	t.Logf("introspect load: n=%d elapsed=%s rps=%.0f p50=%s p95=%s p99=%s",
		len(all), elapsed.Round(time.Millisecond), rps,
		p50.Round(time.Microsecond), p95.Round(time.Microsecond), p99.Round(time.Microsecond))

	// SLO assertions. These include full HTTP round-trip over loopback +
	// a real Postgres lookup, so they are conservative. Thresholds are
	// overridable so shared CI runners (slower than a dev box) can loosen
	// them without disabling the correctness guard above; locally they
	// default to the strict p50<5ms / p99<20ms target.
	p50Max := sloEnv("SESAMO_LOAD_P50_MAX_MS", 5*time.Millisecond)
	p99Max := sloEnv("SESAMO_LOAD_P99_MAX_MS", 20*time.Millisecond)
	if p50 > p50Max {
		t.Errorf("p50 %s exceeds %s SLO", p50, p50Max)
	}
	if p99 > p99Max {
		t.Errorf("p99 %s exceeds %s SLO", p99, p99Max)
	}
}

// sloEnv reads an integer millisecond threshold from the environment,
// falling back to def when unset or unparseable.
func sloEnv(name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	ms, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return time.Duration(ms) * time.Millisecond
}
