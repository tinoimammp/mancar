package dashboard

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tinoimammp/mancar/internal/inspect"
	"github.com/tinoimammp/mancar/internal/router"
	"github.com/tinoimammp/mancar/internal/store/postgres"
)

// Request inspector endpoints. Captures are decrypted here, in memory, only
// for a signed-in account; the database only ever holds ciphertext. Under
// /api/v1/me (scopeUser) an account sees and changes only captures of its
// own tunnels; another account's capture answers 404.

func (d *Dashboard) inspectorOff(w http.ResponseWriter) bool {
	if d.opts.Inspector == nil {
		writeErr(w, http.StatusConflict, "inspector_disabled",
			"the request inspector is off (INSPECT=off, or ENCRYPTION_KEY is missing)")
		return true
	}
	return false
}

type requestSummary struct {
	ID         string    `json:"id"`
	Time       time.Time `json:"time"`
	Hostname   string    `json:"hostname"`
	Method     string    `json:"method"`
	URI        string    `json:"uri"`
	Status     int       `json:"status"`
	DurationMs int64     `json:"duration_ms"`
	ReqSize    int64     `json:"request_size"`
	RespSize   int64     `json:"response_size"`
	Replay     bool      `json:"replay"`
}

func (d *Dashboard) listRequests(w http.ResponseWriter, r *http.Request) {
	if d.inspectorOff(w) {
		return
	}
	q := r.URL.Query()
	f := inspect.Filter{Hostname: strings.TrimSpace(q.Get("host")), UserID: scopeUser(r), Limit: 100}
	if v, err := strconv.Atoi(q.Get("limit")); err == nil {
		f.Limit = v
	}
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "before must be an RFC 3339 time")
			return
		}
		f.Before = t
	}
	rows, err := d.opts.Inspector.Store().ListCaptures(r.Context(), f)
	if err != nil {
		d.internal(w, "list captures", err)
		return
	}
	out := []requestSummary{}
	undecryptable := 0
	for _, row := range rows {
		rec, err := d.opts.Inspector.Sealer().Open(row)
		if err != nil {
			undecryptable++
			continue
		}
		out = append(out, requestSummary{
			ID: row.ID, Time: row.CreatedAt, Hostname: row.Hostname, Method: rec.Method, URI: rec.URI,
			Status: row.Status, DurationMs: row.DurationMs, ReqSize: row.ReqSize, RespSize: row.RespSize, Replay: rec.Replay,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"requests": out, "undecryptable": undecryptable,
		"retention_seconds": int64(d.opts.Inspector.Retention() / time.Second),
		"max_body_bytes":    d.opts.Inspector.MaxBody(),
	})
}

// body is a captured body prepared for display.
type body struct {
	Size      int64  `json:"size"`
	Kept      int    `json:"kept"`
	Truncated bool   `json:"truncated"`
	Text      string `json:"text,omitempty"`   // when the body is UTF-8 text
	Base64    []byte `json:"base64,omitempty"` // otherwise (encoded by encoding/json)
	Decoded   string `json:"decoded,omitempty"`
}

func displayBody(b []byte, size int64, h http.Header) body {
	out := body{Size: size, Kept: len(b), Truncated: int64(len(b)) < size}
	// A complete gzip body is decompressed for display (bounded).
	if strings.EqualFold(h.Get("Content-Encoding"), "gzip") && !out.Truncated && len(b) > 0 {
		if zr, err := gzip.NewReader(bytes.NewReader(b)); err == nil {
			if plain, err := io.ReadAll(io.LimitReader(zr, 1<<20)); err == nil && utf8.Valid(plain) {
				out.Text, out.Decoded = string(plain), "gzip"
				return out
			}
		}
	}
	if utf8.Valid(b) {
		out.Text = string(b)
	} else {
		out.Base64 = b
	}
	return out
}

func (d *Dashboard) getRequest(w http.ResponseWriter, r *http.Request) {
	if d.inspectorOff(w) {
		return
	}
	rec, ok := d.loadCapture(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": rec.ID, "time": rec.Time, "hostname": rec.Hostname, "tunnel_id": rec.TunnelID,
		"method": rec.Method, "uri": rec.URI, "proto": rec.Proto, "client": rec.Client,
		"status": rec.Status, "duration_ms": rec.DurationMs, "replay": rec.Replay,
		"request_headers": rec.ReqHeader, "request_body": displayBody(rec.ReqBody, rec.ReqSize, rec.ReqHeader),
		"response_headers": rec.RespHeader, "response_body": displayBody(rec.RespBody, rec.RespSize, rec.RespHeader),
		"replayable":     replayable(rec) == "",
		"replay_blocker": replayable(rec),
	})
}

func (d *Dashboard) loadCapture(w http.ResponseWriter, r *http.Request) (*inspect.Record, bool) {
	row, err := d.opts.Inspector.Store().GetCapture(r.Context(), r.PathValue("id"))
	if uid := scopeUser(r); err == nil && uid != "" && row.UserID != uid {
		err = postgres.ErrNotFound // someone else's: indistinguishable from missing
	}
	if errors.Is(err, postgres.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "no such request (it may have expired)")
		return nil, false
	}
	if err != nil {
		d.internal(w, "get capture", err)
		return nil, false
	}
	rec, err := d.opts.Inspector.Sealer().Open(row)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "undecryptable", err.Error())
		return nil, false
	}
	return rec, true
}

// replayable returns why a capture cannot be replayed, or "".
func replayable(rec *inspect.Record) string {
	switch {
	case rec.ReqTruncated():
		return "the request body was larger than INSPECT_MAX_BODY_BYTES, so it was not stored completely"
	case rec.ReqHeader.Get("Upgrade") != "":
		return "WebSocket and other upgrade requests cannot be replayed"
	}
	return ""
}

// Headers that describe the original connection, not the request.
var dropOnReplay = []string{
	"Connection", "Keep-Alive", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	"Content-Length", "X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Real-Ip", "Forwarded",
}

func (d *Dashboard) replayRequest(w http.ResponseWriter, r *http.Request) {
	if d.inspectorOff(w) {
		return
	}
	if d.opts.Replay == nil {
		writeErr(w, http.StatusConflict, "replay_unavailable", "replay is not available")
		return
	}
	rec, ok := d.loadCapture(w, r)
	if !ok {
		return
	}
	if why := replayable(rec); why != "" {
		writeErr(w, http.StatusConflict, "not_replayable", why)
		return
	}
	ctx, cancel := context.WithTimeout(router.WithReplay(context.WithoutCancel(r.Context())), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, rec.Method, "http://"+rec.Hostname+rec.URI, bytes.NewReader(rec.ReqBody))
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "bad_capture", "the captured request cannot be rebuilt")
		return
	}
	req.Header = rec.ReqHeader.Clone()
	for _, h := range dropOnReplay {
		req.Header.Del(h)
	}
	req.Host = rec.Hostname
	req.RemoteAddr = "127.0.0.1:0"
	req.RequestURI = rec.URI

	start := time.Now()
	rw := &discardWriter{header: http.Header{}}
	d.opts.Replay.ServeHTTP(rw, req)
	if rw.status == 0 {
		rw.status = http.StatusOK
	}
	d.audit(r, "request.replay", rec.Hostname, fmt.Sprintf("%s %s → %d", rec.Method, rec.URI, rw.status))
	writeJSON(w, http.StatusOK, map[string]any{
		"status": rw.status, "duration_ms": time.Since(start).Milliseconds(), "response_size": rw.n,
	})
}

func (d *Dashboard) clearRequests(w http.ResponseWriter, r *http.Request) {
	if d.inspectorOff(w) {
		return
	}
	host := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host")))
	var n int64
	var err error
	if uid := scopeUser(r); uid != "" {
		n, err = d.clearOwnCaptures(r, uid, host)
	} else {
		n, err = d.opts.Inspector.Store().DeleteCaptures(r.Context(), host)
	}
	if err != nil {
		d.internal(w, "delete captures", err)
		return
	}
	d.audit(r, "requests.clear", host, fmt.Sprintf("%d deleted", n))
	writeJSON(w, http.StatusOK, map[string]int64{"deleted": n})
}

// userCaptureDeleter is implemented by *postgres.Store.
type userCaptureDeleter interface {
	DeleteUserCaptures(ctx context.Context, userID, hostname string) (int64, error)
}

// clearOwnCaptures deletes an account's captures, of one hostname or all.
func (d *Dashboard) clearOwnCaptures(r *http.Request, uid, host string) (int64, error) {
	if del, ok := d.opts.Inspector.Store().(userCaptureDeleter); ok {
		return del.DeleteUserCaptures(r.Context(), uid, host)
	}
	// stores without per-user deletion: only hostnames the account holds
	if host == "" {
		return 0, nil
	}
	if own, err := d.ownsHost(r, uid, host); err != nil || !own {
		return 0, err
	}
	return d.opts.Inspector.Store().DeleteCaptures(r.Context(), host)
}

// discardWriter receives a replayed response; the router's inspector has
// already recorded it, so only the status and size are kept here.
type discardWriter struct {
	header http.Header
	status int
	n      int64
}

func (w *discardWriter) Header() http.Header { return w.header }

func (w *discardWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
}

func (w *discardWriter) Write(b []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	w.n += int64(len(b))
	return len(b), nil
}
