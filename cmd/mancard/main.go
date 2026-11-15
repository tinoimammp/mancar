// Command mancard is the self-hosted tunnel gateway.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/USERNAME/mancar/internal/daemon"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	go func() {
		// After the first signal restore the default behaviour, so a
		// second Ctrl-C terminates immediately if shutdown hangs.
		<-ctx.Done()
		stop()
	}()
	os.Exit(daemon.Main(ctx, os.Args[1:], daemon.OSEnv()))
}
