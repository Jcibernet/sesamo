package email

import (
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"
)

const testWebhookSecret = "whsec_c2VzYW1vLXRlc3Qtd2ViaG9vay1zZWNyZXQtMQ=="

// signedHeaders builds the headers a genuine delivery carries.
func signedHeaders(t *testing.T, secret, svixID string, ts time.Time, body []byte) http.Header {
	t.Helper()
	sig, err := SignSvix(secret, svixID, ts, body)
	if err != nil {
		t.Fatalf("SignSvix: %v", err)
	}
	h := http.Header{}
	h.Set(HeaderSvixID, svixID)
	h.Set(HeaderSvixTimestamp, strconv.FormatInt(ts.Unix(), 10))
	h.Set(HeaderSvixSignature, sig)
	return h
}

func TestVerifySvixAcceptsValidSignature(t *testing.T) {
	body := []byte(`{"type":"email.delivered","data":{"email_id":"abc"}}`)
	now := time.Now()
	h := signedHeaders(t, testWebhookSecret, "msg_2abc", now, body)

	got, err := VerifySvix(testWebhookSecret, h, body, now, WebhookTolerance)
	if err != nil {
		t.Fatalf("VerifySvix: %v", err)
	}
	if got != "msg_2abc" {
		t.Fatalf("svix id = %q", got)
	}
}

// The signature covers the exact bytes received. Re-encoded (even
// semantically identical) JSON must fail, which is why the handler reads
// the raw body once and never marshals it back.
func TestVerifySvixRejectsModifiedBody(t *testing.T) {
	body := []byte(`{"type":"email.delivered","data":{"email_id":"abc"}}`)
	now := time.Now()
	h := signedHeaders(t, testWebhookSecret, "msg_1", now, body)

	tampered := []byte(`{"type":"email.bounced","data":{"email_id":"abc"}}`)
	if _, err := VerifySvix(testWebhookSecret, h, tampered, now, WebhookTolerance); !errors.Is(err, ErrWebhookSignature) {
		t.Fatalf("err = %v, want ErrWebhookSignature", err)
	}
	reordered := []byte(`{"data":{"email_id":"abc"},"type":"email.delivered"}`)
	if _, err := VerifySvix(testWebhookSecret, h, reordered, now, WebhookTolerance); !errors.Is(err, ErrWebhookSignature) {
		t.Fatalf("reordered body err = %v, want ErrWebhookSignature", err)
	}
}

func TestVerifySvixRejectsWrongSecret(t *testing.T) {
	body := []byte(`{}`)
	now := time.Now()
	h := signedHeaders(t, testWebhookSecret, "msg_1", now, body)

	if _, err := VerifySvix("whsec_YW5vdGhlci1zZWNyZXQtZW50aXJlbHk=", h, body, now, WebhookTolerance); !errors.Is(err, ErrWebhookSignature) {
		t.Fatalf("err = %v, want ErrWebhookSignature", err)
	}
}

// Signature alone does not stop replay: an old delivery is still
// correctly signed forever. The timestamp window is what bounds it.
func TestVerifySvixRejectsStaleTimestamp(t *testing.T) {
	body := []byte(`{}`)
	old := time.Now().Add(-30 * time.Minute)
	h := signedHeaders(t, testWebhookSecret, "msg_old", old, body)

	if _, err := VerifySvix(testWebhookSecret, h, body, time.Now(), WebhookTolerance); !errors.Is(err, ErrWebhookTimestamp) {
		t.Fatalf("err = %v, want ErrWebhookTimestamp", err)
	}
	// A timestamp far in the future is equally unacceptable: it would let
	// a captured delivery be held and replayed later.
	future := time.Now().Add(30 * time.Minute)
	hf := signedHeaders(t, testWebhookSecret, "msg_future", future, body)
	if _, err := VerifySvix(testWebhookSecret, hf, body, time.Now(), WebhookTolerance); !errors.Is(err, ErrWebhookTimestamp) {
		t.Fatalf("future err = %v, want ErrWebhookTimestamp", err)
	}
	// Inside the window it verifies.
	recent := time.Now().Add(-2 * time.Minute)
	hr := signedHeaders(t, testWebhookSecret, "msg_recent", recent, body)
	if _, err := VerifySvix(testWebhookSecret, hr, body, time.Now(), WebhookTolerance); err != nil {
		t.Fatalf("in-window delivery rejected: %v", err)
	}
}

// A secret rotation signs one delivery with both secrets; either match
// authenticates it, and unknown versions are ignored rather than fatal.
func TestVerifySvixAcceptsOneOfSeveralSignatures(t *testing.T) {
	body := []byte(`{"type":"email.sent"}`)
	now := time.Now()
	good, err := SignSvix(testWebhookSecret, "msg_multi", now, body)
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set(HeaderSvixID, "msg_multi")
	h.Set(HeaderSvixTimestamp, strconv.FormatInt(now.Unix(), 10))
	h.Set(HeaderSvixSignature, "v1,Zm9yZ2VkLXNpZ25hdHVyZQ== "+good+" v2,dW5rbm93bi12ZXJzaW9u")

	got, err := VerifySvix(testWebhookSecret, h, body, now, WebhookTolerance)
	if err != nil {
		t.Fatalf("VerifySvix: %v", err)
	}
	if got != "msg_multi" {
		t.Fatalf("svix id = %q", got)
	}

	// Only-forged and only-unknown-version lists must not authenticate.
	h.Set(HeaderSvixSignature, "v1,Zm9yZ2VkLXNpZ25hdHVyZQ== v3,"+good)
	if _, err := VerifySvix(testWebhookSecret, h, body, now, WebhookTolerance); !errors.Is(err, ErrWebhookSignature) {
		t.Fatalf("err = %v, want ErrWebhookSignature", err)
	}
}

func TestVerifySvixRejectsMissingHeadersAndBadSecret(t *testing.T) {
	body := []byte(`{}`)
	now := time.Now()
	full := signedHeaders(t, testWebhookSecret, "msg_1", now, body)

	for _, missing := range []string{HeaderSvixID, HeaderSvixTimestamp, HeaderSvixSignature} {
		h := full.Clone()
		h.Del(missing)
		if _, err := VerifySvix(testWebhookSecret, h, body, now, WebhookTolerance); !errors.Is(err, ErrWebhookHeaders) {
			t.Fatalf("missing %s: err = %v, want ErrWebhookHeaders", missing, err)
		}
	}
	for _, secret := range []string{"", "whsec_", "whsec_@@@not-base64@@@"} {
		if _, err := VerifySvix(secret, full, body, now, WebhookTolerance); !errors.Is(err, ErrWebhookSecret) {
			t.Fatalf("secret %q: err = %v, want ErrWebhookSecret", secret, err)
		}
	}
	bad := full.Clone()
	bad.Set(HeaderSvixTimestamp, "not-a-number")
	if _, err := VerifySvix(testWebhookSecret, bad, body, now, WebhookTolerance); !errors.Is(err, ErrWebhookTimestamp) {
		t.Fatalf("err = %v, want ErrWebhookTimestamp", err)
	}
}
