// Package cli implements the phishlens command tree (ТЗ §9).
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/phishlens/phishlens/internal/app"
	"github.com/phishlens/phishlens/internal/buildinfo"
	"github.com/phishlens/phishlens/internal/config"
)

var errNotImplemented = errors.New("not implemented yet — see the TODO in the corresponding package")

var (
	flagConfig   string
	flagLogLevel string
)

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "phishlens",
		Short:         "PhishLens — анализ подозрительных писем: вердикт и объяснение за 5 секунд",
		Version:       buildinfo.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVarP(&flagConfig, "config", "c", "", "путь к config.yaml (по умолчанию configs/config.yaml → config.yaml → configs/config.example.yaml)")
	root.PersistentFlags().StringVar(&flagLogLevel, "log-level", "", "trace|debug|info|warn|error (переопределяет log.level)")

	root.AddCommand(
		newServeCmd(),
		newAnalyzeCmd(),
		newBatchCmd(),
		newEvalCmd(),
		newMigrateCmd(),
		newAPIKeyCmd(),
		newListsCmd(),
		newBrandsCmd(),
		newWeightsCmd(),
		newIOCCmd(),
		newReportCmd(),
		newKeygenCmd(),
		newVersionCmd(),
		newHealthCmd(),
	)
	return root
}

// Execute runs the CLI.
func Execute() error {
	if err := newRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return err
	}
	return nil
}

// loadConfig reads config honoring --config / --log-level.
func loadConfig() (*config.Config, zerolog.Logger, error) {
	cfg, err := config.Load(app.ResolveConfigPath(flagConfig))
	if err != nil {
		return nil, zerolog.Nop(), err
	}
	if flagLogLevel != "" {
		cfg.Log.Level = flagLogLevel
	}
	return cfg, app.NewLogger(cfg.Log), nil
}

// buildApp constructs the app with signal-aware context.
func buildApp(opts app.Options) (*app.App, context.Context, context.CancelFunc, error) {
	cfg, log, err := loadConfig()
	if err != nil {
		return nil, nil, nil, err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	a, err := app.New(ctx, cfg, log, opts)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	return a, ctx, cancel, nil
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Версия и редакция",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "phishlens %s (%s)\n", buildinfo.Version, buildinfo.Edition)
		},
	}
}
