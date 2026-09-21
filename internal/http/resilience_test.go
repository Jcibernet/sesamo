package http

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jcibernet/sesamo/internal/metrics"
)

func TestResilience01_PanicRecovered(t *testing.T) {
	s := &Server{log: testLogger(), metrics: metrics.New()}
	h := s.withRecover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("test panic")
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/any", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("panic response = %d, want 500", rr.Code)
	}
	if got := s.metrics.WritePrometheus(); !strings.Contains(got, "sesamo_http_panics_total 1") {
		t.Fatalf("panic metric missing: %s", got)
	}
}

func TestResilience02_RequestIDEchoAndSanitization(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/healthz", nil)
	req.Header.Set(requestIDHeader, "upstream-42")
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if got := res.Header.Get(requestIDHeader); got != "upstream-42" {
		t.Fatalf("echoed request id = %q, want upstream-42", got)
	}

	for _, bad := range []string{"has space", strings.Repeat("a", 129), "line\nbreak"} {
		if got := validRequestID(bad); got != "" {
			t.Fatalf("validRequestID(%q) = %q, want empty", bad, got)
		}
	}
	if got := newRequestID(); len(got) < 16 {
		t.Fatalf("generated request id too short: %q", got)
	}
}

func TestResilience03_StatusClassCountersAndPoolGauges(t *testing.T) {
	h := newHarness(t)
	c := h.client()
	for _, path := range []string{"/healthz", "/not-a-route"} {
		res, err := c.Get(h.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		res.Body.Close()
	}

	res, err := c.Get(h.srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	text := string(body)
	for _, name := range []string{
		"sesamo_http_requests_total_2xx",
		"sesamo_http_requests_total_4xx",
		"sesamo_request_duration_seconds_count",
		"sesamo_db_pool_acquired",
		"sesamo_db_pool_idle",
		"sesamo_db_pool_max",
	} {
		if !strings.Contains(text, name) {
			t.Fatalf("metrics missing %q:\n%s", name, text)
		}
	}
}
