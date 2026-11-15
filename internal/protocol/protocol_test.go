package protocol

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestMessageRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := Message{Type: TypeRegister, ReqID: "1", Register: &Register{Proto: ProtoHTTP, Subdomain: "my-api"}}
	if err := WriteJSONLine(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadMessage(NewControlReader(&buf))
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != in.Type || out.ReqID != "1" || out.Register.Subdomain != "my-api" {
		t.Fatalf("unexpected message: %+v", out)
	}
}

func TestReadMessageRejectsOversizedLine(t *testing.T) {
	r := strings.NewReader(strings.Repeat("a", MaxLineBytes+10) + "\n")
	if _, err := ReadMessage(NewControlReader(r)); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("want ErrLineTooLong, got %v", err)
	}
}

func TestStreamHeaderDoesNotConsumePayload(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSONLine(&buf, StreamHeader{TunnelID: "abc"}); err != nil {
		t.Fatal(err)
	}
	buf.WriteString("PAYLOAD")
	h, err := ReadStreamHeader(&buf)
	if err != nil || h.TunnelID != "abc" {
		t.Fatalf("header: %+v err=%v", h, err)
	}
	rest, _ := io.ReadAll(&buf)
	if string(rest) != "PAYLOAD" {
		t.Fatalf("payload consumed: %q", rest)
	}
}

func TestStreamHeaderTooLong(t *testing.T) {
	r := strings.NewReader(strings.Repeat("x", 5000))
	if _, err := ReadStreamHeader(r); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("want ErrLineTooLong, got %v", err)
	}
}
