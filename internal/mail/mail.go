// Package mail sends the dashboard's emails (confirm an address, reset a
// password) over SMTP, configured with one URL:
//
//	smtps://user:password@smtp.example.com:465  implicit TLS
//	smtp://user:password@smtp.example.com:587   STARTTLS (required)
//
// Plain-text SMTP without TLS is only accepted for a server on localhost
// (a local relay or a test catcher such as Mailpit).
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

// Message is one plain-text email.
type Message struct {
	To      string
	Subject string
	Body    string
}

// Sender delivers messages.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// SMTP is a Sender for an SMTP server.
type SMTP struct {
	host, port string
	implicit   bool // smtps: TLS from the first byte
	user, pass string
	from       string
	dialer     net.Dialer
}

// ParseURL builds an SMTP sender from SMTP_URL; from is the sender address.
func ParseURL(raw, from string) (*SMTP, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("SMTP_URL: %w", err)
	}
	s := &SMTP{host: u.Hostname(), port: u.Port(), from: from, dialer: net.Dialer{Timeout: 15 * time.Second}}
	switch u.Scheme {
	case "smtps":
		s.implicit = true
		if s.port == "" {
			s.port = "465"
		}
	case "smtp":
		if s.port == "" {
			s.port = "587"
		}
	default:
		return nil, errors.New("SMTP_URL must start with smtps:// (port 465) or smtp:// (port 587, STARTTLS)")
	}
	if s.host == "" {
		return nil, errors.New("SMTP_URL has no host")
	}
	if u.User != nil {
		s.user = u.User.Username()
		s.pass, _ = u.User.Password()
	}
	if _, err := mail.ParseAddress(from); err != nil {
		return nil, fmt.Errorf("sender address %q: %w", from, err)
	}
	return s, nil
}

// Host returns the server host (logs, never the password).
func (s *SMTP) Host() string { return s.host }

func isLocal(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Send delivers m, or returns the error.
func (s *SMTP) Send(ctx context.Context, m Message) error {
	to, err := mail.ParseAddress(m.To)
	if err != nil {
		return fmt.Errorf("mail: bad recipient: %w", err)
	}
	data, err := Compose(s.from, to.Address, m.Subject, m.Body, time.Now())
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(s.host, s.port)
	tlsConf := &tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}

	var conn net.Conn
	if s.implicit {
		conn, err = (&tls.Dialer{NetDialer: &s.dialer, Config: tlsConf}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = s.dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("mail: connect: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("mail: %w", err)
	}
	defer c.Close()
	if !s.implicit {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsConf); err != nil {
				return fmt.Errorf("mail: STARTTLS: %w", err)
			}
		} else if !isLocal(s.host) {
			return errors.New("mail: the server does not offer STARTTLS; use smtps:// or a server that does")
		}
	}
	if s.user != "" {
		// PlainAuth refuses to send the password without TLS (except to localhost).
		if err := c.Auth(smtp.PlainAuth("", s.user, s.pass, s.host)); err != nil {
			return fmt.Errorf("mail: login: %w", err)
		}
	}
	from, _ := mail.ParseAddress(s.from)
	if err := c.Mail(from.Address); err != nil {
		return fmt.Errorf("mail: MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to.Address); err != nil {
		return fmt.Errorf("mail: RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("mail: DATA: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("mail: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mail: send: %w", err)
	}
	return c.Quit()
}

// Compose renders an RFC 5322 message: UTF-8 plain text, quoted-printable.
// Header values are checked for line breaks so no header can be injected.
func Compose(from, to, subject, body string, now time.Time) ([]byte, error) {
	for _, v := range []string{from, to, subject} {
		if strings.ContainsAny(v, "\r\n") {
			return nil, errors.New("mail: line break in a header")
		}
	}
	f, err := mail.ParseAddress(from)
	if err != nil {
		return nil, fmt.Errorf("mail: bad sender: %w", err)
	}
	id := make([]byte, 12)
	rand.Read(id)
	domain := f.Address[strings.LastIndex(f.Address, "@")+1:]

	var b bytes.Buffer
	h := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	h("From", f.String())
	h("To", to)
	h("Subject", mime.QEncoding.Encode("utf-8", subject))
	h("Date", now.UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	h("MIME-Version", "1.0")
	h("Content-Type", `text/plain; charset="utf-8"`)
	h("Content-Transfer-Encoding", "quoted-printable")
	h("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	qp.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
	qp.Close()
	return b.Bytes(), nil
}
