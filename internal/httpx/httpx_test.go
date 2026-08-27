package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewBoundsWholeRequest(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()

	start := time.Now()
	_, err := New(50 * time.Millisecond).Get(slow.URL)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("slow request unexpectedly succeeded")
	}
	if elapsed >= 300*time.Millisecond {
		t.Fatalf("timeout reached after %s, want < 300ms", elapsed)
	}
}
