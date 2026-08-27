// Package httpx builds bounded HTTP clients for calls to third parties.
//
// The standard http.DefaultClient has no total timeout. Authentication paths
// must never let a slow email or OAuth provider hold a handler indefinitely.
package httpx

import (
	"net"
	"net/http"
	"time"
)

const (
	dialTimeout           = 5 * time.Second
	tlsHandshakeTimeout   = 5 * time.Second
	responseHeaderTimeout = 10 * time.Second
	expectContinueTimeout = time.Second
)

// New returns a client with an operation-wide deadline and bounded transport
// phases. timeout must cover the complete request; callers choose it from the
// user-facing latency budget (Sésamo uses 15 seconds for OAuth/email).
func New(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          32,
			MaxIdleConnsPerHost:   8,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ResponseHeaderTimeout: responseHeaderTimeout,
			ExpectContinueTimeout: expectContinueTimeout,
		},
	}
}
