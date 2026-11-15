package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"
)

func TestWireConstants(t *testing.T) {
	// These are part of the agent/gateway contract; changing them breaks
	// deployed agents, so pin them.
	if UpgradeToken != "mancar/1" {
		t.Errorf("UpgradeToken = %q", UpgradeToken)
	}
	if ConnectPath != "/_mancar/v1/connect" {
		t.Errorf("ConnectPath = %q", ConnectPath)
	}
	if MaxLineBytes != 64*1024 {
		t.Errorf("MaxLineBytes = %d", MaxLineBytes)
	}
	if ProtoHTTP != "http" || ProtoTCP != "tcp" {
		t.Errorf("protocols = %q/%q", ProtoHTTP, ProtoTCP)
	}
}

func TestMessageJSONShape(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
		want string
	}{
		{"register", Message{Type: TypeRegister, ReqID: "1", Register: &Register{Proto: ProtoHTTP, Subdomain: "my-api"}},
			`{"type":"register","req_id":"1","register":{"proto":"http","subdomain":"my-api"}}`},
		{"register random", Message{Type: TypeRegister, Register: &Register{Proto: ProtoHTTP}},
			`{"type":"register","register":{"proto":"http"}}`},
		{"ok", Message{Type: TypeOK}, `{"type":"ok"}`},
		{"unregister", Message{Type: TypeUnregister, Unregister: &Unregister{TunnelID: "t1"}},
			`{"type":"unregister","unregister":{"tunnel_id":"t1"}}`},
		{"error", Message{Type: TypeError, Error: &Error{Code: CodeHostnameTaken, Message: "taken"}},
			`{"type":"error","error":{"code":"hostname_taken","message":"taken"}}`},
		{"registered tcp", Message{Type: TypeRegistered, Registered: &Registered{TunnelID: "t", Proto: ProtoTCP, Port: 20001, PublicURL: "tcp://x:20001"}},
			`{"type":"registered","registered":{"tunnel_id":"t","proto":"tcp","port":20001,"public_url":"tcp://x:20001"}}`},
	}
	for _, tc := range tests {
		b, err := json.Marshal(tc.msg)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if string(b) != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, b, tc.want)
		}
	}
}

func TestErrorFormatting(t *testing.T) {
	var err error = &Error{Code: CodeHostnameTaken, Message: "already used"}
	if err.Error() != "hostname_taken: already used" {
		t.Errorf("Error() = %q", err.Error())
	}
	wrapped := errors.Join(errors.New("outer"), err)
	var pe *Error
	if !errors.As(wrapped, &pe) || pe.Code != CodeHostnameTaken {
		t.Error("errors.As should recover *protocol.Error")
	}
}

func TestErrorCodesAreDistinct(t *testing.T) {
	codes := []string{CodeHostnameTaken, CodeHostnameInvalid, CodeLimitExceeded, CodeUnsupported, CodeNotFound, CodeBadRequest, CodeInternal}
	seen := map[string]bool{}
	for _, c := range codes {
		if c == "" || seen[c] {
			t.Errorf("error code %q is empty or duplicated", c)
		}
		seen[c] = true
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

func TestWriteJSONLine(t *testing.T) {
	t.Run("ends with exactly one newline", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteJSONLine(&buf, Message{Type: TypeOK}); err != nil {
			t.Fatal(err)
		}
		if got := buf.String(); got != "{\"type\":\"ok\"}\n" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("embedded newlines are escaped so framing cannot be broken", func(t *testing.T) {
		var buf bytes.Buffer
		msg := Message{Type: TypeRegister, Register: &Register{Proto: ProtoHTTP, Subdomain: "a\nb\r\nc"}}
		if err := WriteJSONLine(&buf, msg); err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(buf.String(), "\n"); n != 1 {
			t.Fatalf("output has %d newlines, want 1: %q", n, buf.String())
		}
		out, err := ReadMessage(NewControlReader(&buf))
		if err != nil || out.Register.Subdomain != "a\nb\r\nc" {
			t.Errorf("round trip failed: %+v %v", out, err)
		}
	})
	t.Run("oversized message writes nothing", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteJSONLine(&buf, Message{Type: TypeOK, ReqID: strings.Repeat("a", MaxLineBytes)})
		if !errors.Is(err, ErrLineTooLong) {
			t.Fatalf("err = %v, want ErrLineTooLong", err)
		}
		if buf.Len() != 0 {
			t.Errorf("%d bytes written despite the error", buf.Len())
		}
	})
	t.Run("unmarshalable value writes nothing", func(t *testing.T) {
		var buf bytes.Buffer
		err := WriteJSONLine(&buf, make(chan int))
		if err == nil || errors.Is(err, ErrLineTooLong) {
			t.Fatalf("err = %v, want a marshalling error", err)
		}
		if buf.Len() != 0 {
			t.Error("bytes written despite the error")
		}
	})
	t.Run("writer errors propagate", func(t *testing.T) {
		if err := WriteJSONLine(errWriter{}, Message{Type: TypeOK}); err == nil || err.Error() != "boom" {
			t.Errorf("err = %v", err)
		}
	})
}

func TestMessageSizeBoundary(t *testing.T) {
	base, _ := json.Marshal(Message{Type: "x", ReqID: "a"})
	n := MaxLineBytes - len(base) // largest ReqID such that json+"\n" == MaxLineBytes

	var buf bytes.Buffer
	if err := WriteJSONLine(&buf, Message{Type: "x", ReqID: strings.Repeat("a", n)}); err != nil {
		t.Fatalf("message exactly at the limit rejected: %v", err)
	}
	if buf.Len() != MaxLineBytes {
		t.Fatalf("encoded size = %d, want %d", buf.Len(), MaxLineBytes)
	}
	out, err := ReadMessage(NewControlReader(&buf))
	if err != nil || len(out.ReqID) != n {
		t.Fatalf("reading a message exactly at the limit failed: %v", err)
	}

	buf.Reset()
	if err := WriteJSONLine(&buf, Message{Type: "x", ReqID: strings.Repeat("a", n+1)}); !errors.Is(err, ErrLineTooLong) {
		t.Errorf("one byte over the limit: err = %v, want ErrLineTooLong", err)
	}
}

func TestReadMessage_Errors(t *testing.T) {
	t.Run("clean EOF", func(t *testing.T) {
		if _, err := ReadMessage(NewControlReader(strings.NewReader(""))); !errors.Is(err, io.EOF) {
			t.Errorf("err = %v, want io.EOF", err)
		}
	})
	t.Run("EOF in the middle of a line", func(t *testing.T) {
		if _, err := ReadMessage(NewControlReader(strings.NewReader(`{"type":"ok"}`))); !errors.Is(err, io.EOF) {
			t.Errorf("err = %v, want io.EOF", err)
		}
	})
	t.Run("malformed JSON", func(t *testing.T) {
		_, err := ReadMessage(NewControlReader(strings.NewReader("{not json}\n")))
		if err == nil || errors.Is(err, ErrLineTooLong) || !strings.Contains(err.Error(), "malformed") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("JSON of the wrong shape", func(t *testing.T) {
		if _, err := ReadMessage(NewControlReader(strings.NewReader("[1,2,3]\n"))); err == nil {
			t.Error("array accepted as a message")
		}
	})
	t.Run("unknown fields are ignored for forward compatibility", func(t *testing.T) {
		m, err := ReadMessage(NewControlReader(strings.NewReader(`{"type":"ok","future":{"x":1}}` + "\n")))
		if err != nil || m.Type != TypeOK {
			t.Errorf("got %+v, %v", m, err)
		}
	})
}

func TestReadMessage_SequenceOnOneReader(t *testing.T) {
	var buf bytes.Buffer
	for _, id := range []string{"1", "2", "3"} {
		if err := WriteJSONLine(&buf, Message{Type: TypeOK, ReqID: id}); err != nil {
			t.Fatal(err)
		}
	}
	br := NewControlReader(&buf)
	for _, want := range []string{"1", "2", "3"} {
		m, err := ReadMessage(br)
		if err != nil || m.ReqID != want {
			t.Fatalf("want req %s, got %+v %v", want, m, err)
		}
	}
	if _, err := ReadMessage(br); !errors.Is(err, io.EOF) {
		t.Errorf("after the last message: err = %v, want io.EOF", err)
	}
}

func TestStreamHeader_Errors(t *testing.T) {
	t.Run("EOF before newline", func(t *testing.T) {
		if _, err := ReadStreamHeader(strings.NewReader(`{"tunnel_id":"abc"}`)); err == nil {
			t.Error("header without newline accepted")
		}
	})
	t.Run("empty stream", func(t *testing.T) {
		if _, err := ReadStreamHeader(strings.NewReader("")); !errors.Is(err, io.EOF) {
			t.Errorf("err = %v, want io.EOF", err)
		}
	})
	t.Run("malformed JSON", func(t *testing.T) {
		_, err := ReadStreamHeader(strings.NewReader("{oops\n"))
		if err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestStreamHeader_SizeBoundary(t *testing.T) {
	overhead := len(mustJSON(t, StreamHeader{}))
	exact := StreamHeader{TunnelID: strings.Repeat("a", 4096-overhead)}
	over := StreamHeader{TunnelID: strings.Repeat("a", 4097-overhead)}

	var buf bytes.Buffer
	if err := WriteJSONLine(&buf, exact); err != nil {
		t.Fatal(err)
	}
	h, err := ReadStreamHeader(&buf)
	if err != nil || h.TunnelID != exact.TunnelID {
		t.Fatalf("header of exactly 4096 bytes rejected: %v", err)
	}

	buf.Reset()
	if err := WriteJSONLine(&buf, over); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStreamHeader(&buf); !errors.Is(err, ErrLineTooLong) {
		t.Errorf("header of 4097 bytes: err = %v, want ErrLineTooLong", err)
	}
}

func TestStreamHeader_OmitsEmptyRemoteAddr(t *testing.T) {
	if got := string(mustJSON(t, StreamHeader{TunnelID: "t"})); got != `{"tunnel_id":"t"}` {
		t.Errorf("got %s", got)
	}
	if got := string(mustJSON(t, StreamHeader{TunnelID: "t", RemoteAddr: "1.2.3.4:5"})); got != `{"tunnel_id":"t","remote_addr":"1.2.3.4:5"}` {
		t.Errorf("got %s", got)
	}
}

func TestStreamHeader_PayloadNewlinesDoNotConfuseFraming(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSONLine(&buf, StreamHeader{TunnelID: "t\nx"}); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("line1\nline2\n")
	h, err := ReadStreamHeader(&buf)
	if err != nil || h.TunnelID != "t\nx" {
		t.Fatalf("header: %+v %v", h, err)
	}
	if rest, _ := io.ReadAll(&buf); string(rest) != "line1\nline2\n" {
		t.Errorf("payload = %q", rest)
	}
}

func TestYamuxConfig(t *testing.T) {
	t.Run("zero keepalive uses 15s default", func(t *testing.T) {
		for _, in := range []time.Duration{0, -time.Second} {
			if got := YamuxConfig(in).KeepAliveInterval; got != 15*time.Second {
				t.Errorf("YamuxConfig(%v).KeepAliveInterval = %v", in, got)
			}
		}
	})
	t.Run("custom keepalive is used", func(t *testing.T) {
		if got := YamuxConfig(3 * time.Second).KeepAliveInterval; got != 3*time.Second {
			t.Errorf("KeepAliveInterval = %v", got)
		}
	})
	t.Run("heartbeat and timeouts are enabled", func(t *testing.T) {
		c := YamuxConfig(0)
		if !c.EnableKeepAlive {
			t.Error("keep-alive must be enabled: it is the session heartbeat")
		}
		if c.ConnectionWriteTimeout <= 0 || c.StreamOpenTimeout <= 0 || c.StreamCloseTimeout <= 0 {
			t.Errorf("timeouts must be positive: %v/%v/%v", c.ConnectionWriteTimeout, c.StreamOpenTimeout, c.StreamCloseTimeout)
		}
		if c.LogOutput != io.Discard {
			t.Error("yamux must not write to stderr")
		}
	})
	t.Run("configuration passes yamux validation", func(t *testing.T) {
		if err := yamux.VerifyConfig(YamuxConfig(0)); err != nil {
			t.Errorf("VerifyConfig: %v", err)
		}
	})
	t.Run("each call returns an independent config", func(t *testing.T) {
		a, b := YamuxConfig(0), YamuxConfig(0)
		a.KeepAliveInterval = time.Hour
		if b.KeepAliveInterval == time.Hour {
			t.Error("configs share state")
		}
	})
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
