// Package app wires configuration, reference data, brands, the signal registry,
// reputation, LLM, scoring and storage into one Analyzer (ТЗ §2).
package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"

	"github.com/phishlens/phishlens/data"
	"github.com/phishlens/phishlens/internal/brands"
	"github.com/phishlens/phishlens/internal/buildinfo"
	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/crypto"
	"github.com/phishlens/phishlens/internal/license"
	"github.com/phishlens/phishlens/internal/llm"
	"github.com/phishlens/phishlens/internal/notify"
	"github.com/phishlens/phishlens/internal/parse"
	"github.com/phishlens/phishlens/internal/refdata"
	"github.com/phishlens/phishlens/internal/reputation"
	"github.com/phishlens/phishlens/internal/sandbox"
	"github.com/phishlens/phishlens/internal/score"
	"github.com/phishlens/phishlens/internal/signals"
	signalsall "github.com/phishlens/phishlens/internal/signals/all"
	"github.com/phishlens/phishlens/internal/store"
	"github.com/phishlens/phishlens/prompts"
)

// Options tune construction.
type Options struct {
	NoStore bool // CLI one-shot analysis without a database
	NoLLM   bool // force-disable LLM regardless of config
	Offline bool // no network reputation lookups (deterministic batch/eval/tests)
}

// App is the composition root.
type App struct {
	Cfg      *config.Config
	Log      zerolog.Logger
	License  *license.License
	Data     *refdata.Data
	Brands   *brands.Matcher
	Registry *signals.Registry
	Parser   *parse.Parser
	Rep      *reputation.Client
	Sandbox  sandbox.Runner
	LLM      *llm.Service
	Score    *score.Engine
	Store    store.Store
	Notify   *notify.Fanout
	Analyzer *Analyzer
}

// New builds the application.
func New(ctx context.Context, cfg *config.Config, log zerolog.Logger, opts Options) (*App, error) {
	a := &App{Cfg: cfg, Log: log, License: license.Load()}
	buildinfo.Edition = string(a.License.Edition)

	var err error
	if a.Data, err = refdata.Load(data.FS, cfg.Analysis.DataDir); err != nil {
		return nil, fmt.Errorf("app: reference data: %w", err)
	}

	bf, err := refdata.OpenPath(data.FS, cfg.Analysis.BrandsFile, "brands.yaml")
	if err != nil {
		return nil, fmt.Errorf("app: brands: %w", err)
	}
	list, err := brands.Load(bf)
	bf.Close()
	if err != nil {
		return nil, err
	}
	a.Brands = brands.NewMatcher(list, a.Data.Homoglyphs)

	wf, err := refdata.OpenPath(data.FS, cfg.Analysis.WeightsFile, "weights.yaml")
	if err != nil {
		return nil, fmt.Errorf("app: weights: %w", err)
	}
	weights, err := score.LoadWeights(wf)
	wf.Close()
	if err != nil {
		return nil, err
	}
	if cfg.Analysis.Thresholds.Phishing > 0 {
		weights.Thresholds = score.Thresholds{Phishing: cfg.Analysis.Thresholds.Phishing, Suspicious: cfg.Analysis.Thresholds.Suspicious}
	}
	a.Score = score.NewEngine(weights)

	a.Registry = signalsall.New()
	a.Parser = parse.New()
	a.Parser.Shorteners = a.Data.Shorteners
	a.Parser.Limits.MaxAttachment = int64(cfg.Server.MaxUploadMB) << 20
	if !opts.Offline && cfg.Reputation.LinkExpansion.Enabled {
		a.Parser.ExpandShorteners = true
		a.Parser.MaxRedirects = cfg.Reputation.LinkExpansion.MaxRedirects
		a.Parser.ExpansionTimeout = cfg.Reputation.LinkExpansion.Timeout
	}
	if cfg.OCR.Mode == "tesseract" && cfg.OCR.TesseractURL != "" {
		a.Parser.OCR = parse.NewTesseractOCR(cfg.OCR.TesseractURL)
	}

	if !opts.Offline {
		a.Rep = reputation.New(cfg.Reputation, cfg.AuthChecks.DNSResolver, log)
		if cfg.Sandbox.Enabled {
			a.Sandbox = sandbox.New(cfg.Sandbox.URL, cfg.Sandbox.Screenshot)
		}
	}

	if !opts.NoLLM {
		if a.LLM, err = llm.NewService(cfg.LLM, prompts.FS, cfg.Analysis.PromptsDir, log); err != nil {
			return nil, fmt.Errorf("app: llm: %w", err)
		}
	}
	if cfg.OCR.Mode == "vision_llm" && a.LLM != nil {
		a.Parser.OCR = parse.NewVisionOCR(func(ctx context.Context, image []byte, mime string) (string, error) {
			return a.LLM.Vision(ctx, image, mime)
		})
	}

	if !opts.NoStore {
		st, err := store.Open(cfg.Storage)
		if err != nil {
			return nil, err
		}
		if err := st.Migrate(ctx); err != nil {
			st.Close()
			return nil, err
		}
		if s, ok := st.(*store.SQLite); ok {
			if c, err := crypto.FromEnv(cfg.Storage.EncryptionKeyEnv); err != nil {
				st.Close()
				return nil, err
			} else if c != nil {
				s.SetCipher(c)
			} else if cfg.Storage.StoreBodies {
				log.Warn().Msg("storage.store_bodies=true but no encryption key in env; bodies stored unencrypted")
			}
		}
		a.Store = st
		if a.Rep != nil {
			a.Rep.SetPersistentCache(a.Store)
		}
		// custom brands from DB (F-4.3.4)
		if cfg.Analysis.CustomBrandsEnabled {
			if custom, err := st.ListBrands(ctx, ""); err == nil {
				for _, b := range custom {
					a.Brands.Add(b)
				}
			}
		}
	}

	a.Notify = notify.NewFanout(cfg.Integrations, log)
	if a.Store != nil {
		a.Notify.SetWebhookStore(a.Store)
	}
	a.Analyzer = NewAnalyzer(a)
	log.Info().
		Str("version", buildinfo.Version).
		Str("edition", buildinfo.Edition).
		Int("signals", a.Registry.Len()).
		Int("brands", len(a.Brands.Brands())).
		Bool("llm", a.LLM != nil).
		Bool("store", a.Store != nil).
		Msg("phishlens initialised")
	return a, nil
}

// Close releases resources.
func (a *App) Close() error {
	if a.Store != nil {
		return a.Store.Close()
	}
	return nil
}

// NewLogger builds the zerolog logger per config.
func NewLogger(cfg config.Log) zerolog.Logger {
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	var l zerolog.Logger
	if cfg.Pretty {
		l = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})
	} else {
		l = zerolog.New(os.Stderr)
	}
	return l.Level(level).With().Timestamp().Logger()
}

// ResolveConfigPath returns the first existing candidate for --config.
func ResolveConfigPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	for _, p := range []string{"configs/config.yaml", "config.yaml", filepath.Join("configs", "config.example.yaml")} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
