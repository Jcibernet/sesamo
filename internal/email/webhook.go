package email

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jcibernet/sesamo/internal/crypto"
)

// Svix webhook headers (Resend delivers through Svix).
const (
	HeaderSvixID        = "svix-id"
	HeaderSvixTimestamp = "svix-timestamp"
	HeaderSvixSignature = "svix-signature"
)

// WebhookTolerance is the accepted clock skew for a webhook timestamp. A
// short window is what turns signature verification into replay
// protection for anything older than the dedup table's retention.
const WebhookTolerance = 5 * time.Minute

// Webhook verification failures. The caller answers 401 for all of them:
// distinguishing them for a client would only help an attacker tune.
var (
	ErrWebhookHeaders   = errors.New("email: webhook is missing svix headers")
	ErrWebhookSecret    = errors.New("email: malformed webhook signing secret")
	ErrWebhookTimestamp = errors.New("email: webhook timestamp outside tolerance")
	ErrWebhookSignature = errors.New("email: webhook signature mismatch")
)

// VerifySvix authenticates a webhook delivery over its RAW body and
// returns the svix message id (the deduplication key).
//
// The signed content is "<id>.<timestamp>.<body>" HMAC-SHA256'd with the
// secret, base64 standard-encoded. The body MUST be the exact bytes
// received: re-encoding parsed JSON changes the signature and would make
// verification unfalsifiable in the wrong direction (always failing) or,
// worse, tempt a caller into skipping it.
//
// svix-signature carries a space-separated list of "v<version>,<sig>"
// entries, because a secret rotation signs one delivery with both
// secrets. Any v1 entry matching in constant time authenticates the
// request; unknown versions are ignored.
func VerifySvix(secret string, headers http.Header, body []byte, now time.Time, tolerance time.Duration) (string, error) {
	svixID := strings.TrimSpace(headers.Get(HeaderSvixID))
	timestamp := strings.TrimSpace(headers.Get(HeaderSvixTimestamp))
	signatures := strings.TrimSpace(headers.Get(HeaderSvixSignature))
	if svixID == "" || timestamp == "" || signatures == "" {
		return "", ErrWebhookHeaders
	}

	key, err := decodeWebhookSecret(secret)
	if err != nil {
		return "", err
	}

	secs, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return "", ErrWebhookTimestamp
	}
	if drift := now.Sub(time.Unix(secs, 0)); drift > tolerance || drift < -tolerance {
		return "", ErrWebhookTimestamp
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(svixID))
	mac.Write([]byte("."))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	want := []byte(base64.StdEncoding.EncodeToString(mac.Sum(nil)))

	matched := false
	for _, entry := range strings.Fields(signatures) {
		version, sig, ok := strings.Cut(entry, ",")
		if !ok || version != "v1" {
			continue
		}
		// No early exit: every candidate is compared so the loop's timing
		// does not reveal which entry matched.
		if crypto.SafeEqual([]byte(sig), want) {
			matched = true
		}
	}
	if !matched {
		return "", ErrWebhookSignature
	}
	return svixID, nil
}

// decodeWebhookSecret accepts the "whsec_<base64>" form Svix/Resend hand
// out, and a bare base64 secret for operators who strip the prefix.
func decodeWebhookSecret(secret string) ([]byte, error) {
	secret = strings.TrimSpace(secret)
	secret = strings.TrimPrefix(secret, "whsec_")
	if secret == "" {
		return nil, ErrWebhookSecret
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if key, err := enc.DecodeString(secret); err == nil && len(key) > 0 {
			return key, nil
		}
	}
	return nil, ErrWebhookSecret
}

// SignSvix produces the header value a valid delivery would carry. It
// exists so tests can exercise the endpoint end to end with a real
// signature instead of a bypass, which is the only way a signature check
// stays honest.
func SignSvix(secret, svixID string, timestamp time.Time, body []byte) (string, error) {
	key, err := decodeWebhookSecret(secret)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(svixID))
	mac.Write([]byte("."))
	mac.Write([]byte(strconv.FormatInt(timestamp.Unix(), 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}
