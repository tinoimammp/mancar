package protocol

import (
	"io"
	"time"

	"github.com/hashicorp/yamux"
)

// YamuxConfig is shared by gateway and agent so both ends agree on
// multiplexing and heartbeat behaviour. Keep-alive pings are the session
// heartbeat: a peer that does not answer within ConnectionWriteTimeout
// causes the session to be closed. Per-stream flow-control windows (256 KiB
// by default) provide backpressure.
func YamuxConfig(keepAlive time.Duration) *yamux.Config {
	if keepAlive <= 0 {
		keepAlive = 15 * time.Second
	}
	c := yamux.DefaultConfig()
	c.EnableKeepAlive = true
	c.KeepAliveInterval = keepAlive
	c.ConnectionWriteTimeout = 10 * time.Second
	c.StreamOpenTimeout = 30 * time.Second
	c.StreamCloseTimeout = time.Minute
	c.LogOutput = io.Discard
	return c
}
