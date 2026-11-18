package mail_test

import (
	"strings"
	"testing"
	"time"

	"github.com/tinoimammp/mancar/internal/mail"
)

func TestParseURL(t *testing.T) {
	for _, c := range []struct {
		raw, host string
		ok        bool
	}{
		{"smtps://resend:re_x@smtp.resend.com:465", "smtp.resend.com", true},
		{"smtp://user:p%40ss@mail.example.com", "mail.example.com", true},
		{"smtp://localhost:1025", "localhost", true},
		{"http://mail.example.com", "", false},
		{"smtps://", "", false},
		{"not a url", "", false},
	} {
		s, err := mail.ParseURL(c.raw, "mancar <no-reply@tunnel.example.com>")
		if (err == nil) != c.ok {
			t.Errorf("%q: err=%v, want ok=%v", c.raw, err, c.ok)
			continue
		}
		if c.ok && s.Host() != c.host {
			t.Errorf("%q: host %q", c.raw, s.Host())
		}
	}
	if _, err := mail.ParseURL("smtps://h:465", "not an address"); err == nil {
		t.Error("bad sender accepted")
	}
}

func TestComposeRefusesHeaderInjection(t *testing.T) {
	if _, err := mail.Compose("a@example.com", "b@example.com\r\nBcc: evil@example.com", "hi", "body", time.Now()); err == nil {
		t.Error("recipient with a line break accepted")
	}
	if _, err := mail.Compose("a@example.com", "b@example.com", "hi\nBcc: x", "body", time.Now()); err == nil {
		t.Error("subject with a line break accepted")
	}
}

func TestCompose(t *testing.T) {
	msg, err := mail.Compose("mancar <no-reply@tunnel.example.com>", "you@example.com", "Confirm your email — mancar",
		"Open this link:\nhttps://tunnel.example.com/dashboard/#verify=abc\n", time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	s := string(msg)
	for _, want := range []string{
		"From: \"mancar\" <no-reply@tunnel.example.com>\r\n", "To: you@example.com\r\n",
		"Subject: =?utf-8?q?", "Content-Transfer-Encoding: quoted-printable\r\n",
		"Message-ID: <", "@tunnel.example.com>\r\n", "\r\n\r\nOpen this link:\r\n",
		"#verify=3Dabc", // quoted-printable encodes "="
	} {
		if !strings.Contains(s, want) {
			t.Errorf("message lacks %q:\n%s", want, s)
		}
	}
}
