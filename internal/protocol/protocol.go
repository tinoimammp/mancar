// Package protocol defines the wire contract between the tunnel agent and the
// tunnel gateway. See docs/protocol.md for the full description.
//
// Summary:
//
//  1. The agent opens a TCP (normally TLS) connection to the gateway and sends
//     an HTTP/1.1 Upgrade request to ConnectPath carrying its bearer token.
//  2. On "101 Switching Protocols" both sides speak yamux over the connection.
//  3. The agent opens the first yamux stream: the control stream. It carries
//     newline-delimited JSON Messages (request/response, correlated by ReqID).
//  4. For every public connection the gateway opens a new yamux stream, writes
//     one StreamHeader line and then raw bytes of the proxied connection.
package protocol

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	// UpgradeToken is the value of the Upgrade header for protocol version 1.
	UpgradeToken = "mancar/1"
	// ConnectPath is the gateway endpoint agents connect to.
	ConnectPath = "/_mancar/v1/connect"
	// HeaderInstance identifies one agent process across reconnects.
	HeaderInstance = "X-Mancar-Instance"
	// HeaderAgentVersion carries the agent build version (informational).
	HeaderAgentVersion = "X-Mancar-Agent-Version"
	// HeaderFeatures lists optional features the agent supports
	// (comma-separated). Gateways ignore features they do not know, and only
	// use a feature the agent announced, so either side can be older.
	HeaderFeatures = "X-Mancar-Features"
	// FeatureEvents: the agent accepts an events stream (request log).
	FeatureEvents = "events"

	// MaxLineBytes bounds every control message and stream header.
	MaxLineBytes = 64 * 1024
)

// Tunnel protocols.
const (
	ProtoHTTP = "http"
	ProtoTCP  = "tcp"
)

// Message types on the control stream.
const (
	TypeRegister   = "register"
	TypeRegistered = "registered"
	TypeUnregister = "unregister"
	TypeOK         = "ok"
	TypeError      = "error"
)

// Error codes returned in Error.Code.
const (
	CodeHostnameTaken   = "hostname_taken"
	CodeHostnameInvalid = "hostname_invalid"
	CodeLimitExceeded   = "limit_exceeded"
	CodeUnsupported     = "unsupported"
	CodeNotFound        = "not_found"
	CodeBadRequest      = "bad_request"
	CodeInternal        = "internal"
)

// Message is the envelope for everything on the control stream.
type Message struct {
	Type       string      `json:"type"`
	ReqID      string      `json:"req_id,omitempty"`
	Register   *Register   `json:"register,omitempty"`
	Registered *Registered `json:"registered,omitempty"`
	Unregister *Unregister `json:"unregister,omitempty"`
	Error      *Error      `json:"error,omitempty"`
}

// Register asks the gateway to create a tunnel.
type Register struct {
	Proto string `json:"proto"`
	// Subdomain is a single DNS label for HTTP tunnels. Empty means "assign
	// a random one".
	Subdomain string `json:"subdomain,omitempty"`
}

// Registered confirms a tunnel.
type Registered struct {
	TunnelID  string `json:"tunnel_id"`
	Proto     string `json:"proto"`
	Hostname  string `json:"hostname,omitempty"`
	Port      int    `json:"port,omitempty"`
	PublicURL string `json:"public_url"`
}

// Unregister removes one tunnel while keeping the session.
type Unregister struct {
	TunnelID string `json:"tunnel_id"`
}

// Error is a structured failure.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

// StreamHeader is the first line the gateway writes on each data stream.
type StreamHeader struct {
	TunnelID   string `json:"tunnel_id"`
	RemoteAddr string `json:"remote_addr,omitempty"`
	// Kind is empty for a proxied connection. StreamKindEvents marks the
	// single stream that carries Event lines to an agent announcing
	// FeatureEvents.
	Kind string `json:"kind,omitempty"`
}

// StreamKindEvents is the StreamHeader.Kind of the events stream.
const StreamKindEvents = "events"

// Event reports one finished exchange on a tunnel, for the agent's request
// log. For HTTP it is one request; for TCP one connection.
type Event struct {
	TunnelID   string    `json:"tunnel_id"`
	Time       time.Time `json:"time"`
	Method     string    `json:"method,omitempty"`
	Path       string    `json:"path,omitempty"` // without the query string
	Status     int       `json:"status,omitempty"`
	DurationMs int64     `json:"duration_ms"`
	BytesIn    int64     `json:"bytes_in"`  // from the public client
	BytesOut   int64     `json:"bytes_out"` // to the public client
	Remote     string    `json:"remote,omitempty"`
}

// ErrLineTooLong is returned when a peer exceeds MaxLineBytes.
var ErrLineTooLong = errors.New("protocol: line exceeds maximum size")

// WriteJSONLine writes v as a single JSON line.
func WriteJSONLine(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b)+1 > MaxLineBytes {
		return ErrLineTooLong
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

// NewControlReader returns a reader sized so that ReadMessage enforces
// MaxLineBytes.
func NewControlReader(r io.Reader) *bufio.Reader {
	return bufio.NewReaderSize(r, MaxLineBytes)
}

// ReadMessage reads one control Message from a reader created with
// NewControlReader.
func ReadMessage(br *bufio.Reader) (*Message, error) {
	line, err := br.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, ErrLineTooLong
		}
		return nil, err
	}
	var m Message
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, fmt.Errorf("protocol: malformed message: %w", err)
	}
	return &m, nil
}

// ReadStreamHeader reads the header line from a data stream without consuming
// any payload byte after the newline (so it reads byte by byte; headers are
// tiny).
func ReadStreamHeader(r io.Reader) (*StreamHeader, error) {
	buf := make([]byte, 0, 128)
	one := make([]byte, 1)
	for {
		if _, err := io.ReadFull(r, one); err != nil {
			return nil, err
		}
		if one[0] == '\n' {
			break
		}
		buf = append(buf, one[0])
		if len(buf) > 4096 {
			return nil, ErrLineTooLong
		}
	}
	var h StreamHeader
	if err := json.Unmarshal(buf, &h); err != nil {
		return nil, fmt.Errorf("protocol: malformed stream header: %w", err)
	}
	return &h, nil
}
