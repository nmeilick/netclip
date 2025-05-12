package server

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

// HandleSignals sets up signal handling for graceful shutdown and reload
func (s *Server) HandleSignals(srv *http.Server) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGHUP:
				s.logger.Info().Msg("Received SIGHUP, but doing nothing")
			case syscall.SIGINT, syscall.SIGTERM:
				// Graceful shutdown
				s.logger.Info().Str("signal", sig.String()).Msg("Shutting down gracefully")

				// Stop the cleanup routines
				close(s.StopCleanup)

				// Stop ACME manager if enabled
				if s.acmeMgr != nil {
					s.acmeMgr.Stop()
				}

				// Create a context with timeout for shutdown
				gracefulTimeout := s.Config.Listen.GetGracefulTimeout()

				ctx, cancel := context.WithTimeout(context.Background(), gracefulTimeout)
				defer cancel()

				// Attempt graceful shutdown
				if err := srv.Shutdown(ctx); err != nil {
					s.logger.Error().Err(err).Msg("Server shutdown error")
				}

				// Close loggers
				if s.accessLogger != nil {
					s.accessLogger.Close()
				}
				if s.errorLogger != nil {
					s.errorLogger.Close()
				}

				// Exit with success status
				os.Exit(0)
			}
		}
	}()
}
