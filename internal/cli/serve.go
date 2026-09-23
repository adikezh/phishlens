package cli

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spf13/cobra"

	"github.com/phishlens/phishlens/internal/app"
	"github.com/phishlens/phishlens/internal/httpapi"
	"github.com/phishlens/phishlens/internal/ingest"
	"github.com/phishlens/phishlens/internal/ingest/graph"
	"github.com/phishlens/phishlens/internal/ingest/imap"
	"github.com/phishlens/phishlens/internal/ingest/telegram"
	"github.com/phishlens/phishlens/internal/web"
)

func newServeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Запустить HTTP-сервер (API + UI) и включённые приёмники",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, ctx, cancel, err := buildApp(app.Options{})
			if err != nil {
				return err
			}
			defer cancel()
			defer a.Close()

			api := httpapi.New(a)
			ui, err := web.New(a)
			if err != nil {
				return err
			}
			handler := api.Handler(func(r chi.Router) { ui.Routes(r) })

			ingest.NewManager(a.Log,
				imap.New(a.Cfg.Ingest.IMAP),
				graph.New(a.Cfg.Ingest.Graph),
				telegram.New(a.Cfg.Ingest.Telegram),
			).Start(ctx)
			go retentionLoop(ctx, a)

			srv := &http.Server{
				Addr:              a.Cfg.Server.Listen,
				Handler:           handler,
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       60 * time.Second,
				WriteTimeout:      90 * time.Second,
				IdleTimeout:       120 * time.Second,
				MaxHeaderBytes:    1 << 20,
			}
			errCh := make(chan error, 1)
			go func() {
				a.Log.Info().Str("listen", a.Cfg.Server.Listen).Str("base_url", a.Cfg.Server.BaseURL).Msg("http server started")
				errCh <- srv.ListenAndServe() // TODO: TLS (server.tls.cert/key) or terminate at the ingress
			}()
			select {
			case err := <-errCh:
				if !errors.Is(err, http.ErrServerClosed) {
					return err
				}
			case <-ctx.Done():
				a.Log.Info().Msg("shutting down")
				shutdownCtx, c := context.WithTimeout(context.Background(), 15*time.Second)
				defer c()
				return srv.Shutdown(shutdownCtx)
			}
			return nil
		},
	}
}

// retentionLoop purges submissions older than storage.retention.submissions once an hour.
func retentionLoop(ctx context.Context, a *app.App) {
	d, err := a.Cfg.Storage.Retention.SubmissionsDuration()
	if err != nil || d <= 0 || a.Store == nil {
		return
	}
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		n, err := a.Store.PurgeOlderThan(ctx, time.Now().Add(-d))
		if err != nil {
			a.Log.Warn().Err(err).Msg("retention purge")
		} else if n > 0 {
			a.Log.Info().Int64("deleted", n).Msg("retention purge")
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
