// Package ingest hosts non-HTTP receivers (ТЗ §4.1): IMAP mailbox (F-4.1.4),
// Microsoft Graph (F-4.1.5) and Telegram bot (F-4.1.8). Web/API/add-ins enter via
// internal/httpapi. Each receiver is a Runner started by `serve` when enabled.
package ingest

import (
	"context"
	"errors"

	"github.com/rs/zerolog"
)

// ErrNotImplemented marks stubbed receivers.
var ErrNotImplemented = errors.New("ingest: not implemented")

// Runner is a long-running receiver.
type Runner interface {
	Name() string
	Run(ctx context.Context) error
}

// Manager starts enabled receivers and logs failures without crashing the server.
type Manager struct {
	runners []Runner
	log     zerolog.Logger
}

// NewManager creates a manager.
func NewManager(log zerolog.Logger, runners ...Runner) *Manager {
	return &Manager{runners: runners, log: log}
}

// Start launches each runner in its own goroutine.
func (m *Manager) Start(ctx context.Context) {
	for _, r := range m.runners {
		go func(r Runner) {
			if err := r.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				if errors.Is(err, ErrNotImplemented) {
					m.log.Warn().Str("receiver", r.Name()).Msg("receiver enabled in config but not implemented yet")
					return
				}
				m.log.Error().Err(err).Str("receiver", r.Name()).Msg("receiver stopped")
			}
		}(r)
	}
}
