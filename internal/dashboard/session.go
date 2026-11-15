package dashboard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// A session is a signed, self-contained cookie value:
//
//	base64url(json claims) "." base64url(HMAC-SHA256(key, json claims))
//
// The key is derived from JWT_SECRET. Claims are re-checked against the
// database on every request (the admin must still exist and must not have
// changed password since the session was issued), so deleting an admin or
// resetting a password ends their sessions at once.
type claims struct {
	AdminID  string `json:"a"`
	Username string `json:"u"`
	IssuedMs int64  `json:"i"`
	Expires  int64  `json:"e"`
}

var errBadSession = errors.New("dashboard: invalid session")

type signer struct{ key []byte }

func newSigner(secret string) signer {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("mancar dashboard session v1"))
	return signer{key: m.Sum(nil)}
}

func (s signer) mac(payload []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write(payload)
	return m.Sum(nil)
}

func (s signer) sign(c claims) string {
	payload, _ := json.Marshal(c)
	b64 := base64.RawURLEncoding
	return b64.EncodeToString(payload) + "." + b64.EncodeToString(s.mac(payload))
}

func (s signer) verify(value string, now time.Time) (claims, error) {
	p, sig, ok := strings.Cut(value, ".")
	if !ok || len(value) > 1024 {
		return claims{}, errBadSession
	}
	b64 := base64.RawURLEncoding
	payload, err1 := b64.DecodeString(p)
	got, err2 := b64.DecodeString(sig)
	if err1 != nil || err2 != nil || !hmac.Equal(got, s.mac(payload)) {
		return claims{}, errBadSession
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil || c.AdminID == "" {
		return claims{}, errBadSession
	}
	if now.Unix() >= c.Expires {
		return claims{}, errBadSession
	}
	return c, nil
}
