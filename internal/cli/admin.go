package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/spf13/cobra"

	"github.com/phishlens/phishlens/internal/app"
	"github.com/phishlens/phishlens/internal/brands"
	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/crypto"
	"github.com/phishlens/phishlens/internal/httpapi"
	"github.com/phishlens/phishlens/internal/report"
	"github.com/phishlens/phishlens/internal/store"
)

func contextBackground() context.Context { return context.Background() }

// openStore opens the configured store without the full app (fast admin commands).
func openStore() (store.Store, *config.Config, error) {
	cfg, _, err := loadConfig()
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Open(cfg.Storage)
	if err != nil {
		return nil, nil, err
	}
	if err := st.Migrate(context.Background()); err != nil {
		st.Close()
		return nil, nil, err
	}
	return st, cfg, nil
}

func newMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "migrate", Short: "Миграции БД"}
	cmd.AddCommand(
		&cobra.Command{
			Use: "up", Short: "Применить миграции",
			RunE: func(cmd *cobra.Command, _ []string) error {
				st, _, err := openStore()
				if err != nil {
					return err
				}
				defer st.Close()
				if s, ok := st.(*store.SQLite); ok {
					v, _ := store.MigrationVersion(context.Background(), s.DB())
					fmt.Fprintf(cmd.OutOrStdout(), "schema version: %d\n", v)
				}
				return nil
			},
		},
		&cobra.Command{
			Use: "down", Short: "Откатить последнюю миграцию",
			RunE: func(cmd *cobra.Command, _ []string) error {
				st, _, err := openStore()
				if err != nil {
					return err
				}
				defer st.Close()
				s, ok := st.(*store.SQLite)
				if !ok {
					return errNotImplemented
				}
				if err := s.MigrateDown(context.Background()); err != nil {
					return err
				}
				v, _ := store.MigrationVersion(context.Background(), s.DB())
				fmt.Fprintf(cmd.OutOrStdout(), "schema version: %d\n", v)
				return nil
			},
		},
		&cobra.Command{
			Use: "status", Short: "Текущая версия схемы",
			RunE: func(cmd *cobra.Command, _ []string) error {
				st, _, err := openStore()
				if err != nil {
					return err
				}
				defer st.Close()
				if s, ok := st.(*store.SQLite); ok {
					v, _ := store.MigrationVersion(context.Background(), s.DB())
					fmt.Fprintf(cmd.OutOrStdout(), "schema version: %d\n", v)
				}
				return nil
			},
		},
	)
	return cmd
}

func newAPIKeyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "apikey", Short: "API-ключи"}
	var name, role, org string
	create := &cobra.Command{
		Use: "create", Short: "Создать ключ (показывается один раз)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			switch role {
			case httpapi.RoleUser, httpapi.RoleAnalyst, httpapi.RoleAdmin:
			default:
				return fmt.Errorf("role must be user|analyst|admin")
			}
			st, _, err := openStore()
			if err != nil {
				return err
			}
			defer st.Close()
			key, err := httpapi.GenerateKey()
			if err != nil {
				return err
			}
			k := store.APIKey{ID: ulid.Make().String(), OrgID: org, Name: name, Role: role, KeyHash: httpapi.HashKey(key), CreatedAt: time.Now()}
			if err := st.CreateAPIKey(context.Background(), k); err != nil {
				return err
			}
			_ = st.Audit(context.Background(), store.AuditEntry{OrgID: org, Actor: "cli", Action: "apikey.create", Target: k.ID, Details: name + "/" + role})
			fmt.Fprintf(cmd.OutOrStdout(), "id:   %s\nname: %s\nrole: %s\nkey:  %s\n\nСохраните ключ — повторно он не показывается.\n", k.ID, name, role, key)
			return nil
		},
	}
	create.Flags().StringVar(&name, "name", "default", "имя ключа")
	create.Flags().StringVar(&role, "role", httpapi.RoleUser, "user|analyst|admin")
	create.Flags().StringVar(&org, "org", "", "org id (пусто = глобальный)")
	list := &cobra.Command{
		Use: "list", Short: "Список ключей",
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, _, err := openStore()
			if err != nil {
				return err
			}
			defer st.Close()
			keys, err := st.ListAPIKeys(context.Background(), org)
			if err != nil {
				return err
			}
			for _, k := range keys {
				status := "active"
				if k.RevokedAt != nil {
					status = "revoked"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s  %-20s %-8s %-8s %s\n", k.ID, k.Name, k.Role, status, k.CreatedAt.Format("2006-01-02"))
			}
			return nil
		},
	}
	list.Flags().StringVar(&org, "org", "", "org id")
	revoke := &cobra.Command{
		Use: "revoke <id>", Short: "Отозвать ключ", Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			st, _, err := openStore()
			if err != nil {
				return err
			}
			defer st.Close()
			return st.RevokeAPIKey(context.Background(), args[0])
		},
	}
	cmd.AddCommand(create, list, revoke)
	return cmd
}

func newListsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "lists", Short: "Allow/block-списки организации"}
	for _, kind := range []store.ListKind{store.ListAllow, store.ListBlock} {
		kind := kind
		var org string
		k := &cobra.Command{Use: string(kind), Short: string(kind) + "-список"}
		add := &cobra.Command{
			Use: "add <domain|address>", Args: cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				st, _, err := openStore()
				if err != nil {
					return err
				}
				defer st.Close()
				return st.AddEntry(context.Background(), store.ListEntry{OrgID: org, Kind: kind, Value: args[0], CreatedBy: "cli"})
			},
		}
		remove := &cobra.Command{
			Use: "remove <domain|address>", Args: cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				st, _, err := openStore()
				if err != nil {
					return err
				}
				defer st.Close()
				return st.RemoveEntry(context.Background(), org, kind, args[0])
			},
		}
		list := &cobra.Command{
			Use: "list",
			RunE: func(cmd *cobra.Command, _ []string) error {
				st, _, err := openStore()
				if err != nil {
					return err
				}
				defer st.Close()
				entries, err := st.ListEntries(context.Background(), org, kind)
				if err != nil {
					return err
				}
				for _, e := range entries {
					fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\n", e.Value, e.Note)
				}
				return nil
			},
		}
		k.PersistentFlags().StringVar(&org, "org", "", "org id")
		k.AddCommand(add, remove, list)
		cmd.AddCommand(k)
	}
	return cmd
}

func newBrandsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "brands", Short: "Бренды (встроенные + кастомные)"}
	var name, domains, esp, keywords, locale, org string
	add := &cobra.Command{
		Use: "add", Short: "Добавить кастомный бренд организации",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if name == "" || domains == "" {
				return fmt.Errorf("--name and --domains are required")
			}
			st, _, err := openStore()
			if err != nil {
				return err
			}
			defer st.Close()
			b := brands.Brand{OrgID: org, Name: name, Domains: splitCSV(domains), ESPDomains: splitCSV(esp), Keywords: splitCSV(keywords), Locale: locale}
			if err := st.AddBrand(context.Background(), b); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "brand %q saved\n", name)
			return nil
		},
	}
	add.Flags().StringVar(&name, "name", "", "имя")
	add.Flags().StringVar(&domains, "domains", "", "официальные домены через запятую")
	add.Flags().StringVar(&esp, "esp", "", "ESP-домены через запятую")
	add.Flags().StringVar(&keywords, "keywords", "", "ключевые слова через запятую")
	add.Flags().StringVar(&locale, "locale", "kz", "kz|ru|global")
	add.Flags().StringVar(&org, "org", "", "org id")
	list := &cobra.Command{
		Use: "list", Short: "Список брендов",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, _, cancel, err := buildApp(app.Options{NoLLM: true})
			if err != nil {
				return err
			}
			defer cancel()
			defer a.Close()
			for _, b := range a.Brands.Brands() {
				fmt.Fprintf(cmd.OutOrStdout(), "%-32s %-6s %s\n", b.Name, b.Locale, strings.Join(b.Domains, ","))
			}
			return nil
		},
	}
	cmd.AddCommand(add, list)
	return cmd
}

func newReportCmd() *cobra.Command {
	var period, format, out, org string
	cmd := &cobra.Command{
		Use: "report", Short: "Отчёт за период (md реализован; docx/pdf — TODO)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			d, err := periodDuration(period)
			if err != nil {
				return err
			}
			st, _, err := openStore()
			if err != nil {
				return err
			}
			defer st.Close()
			b, err := report.Generate(context.Background(), st, org, time.Now().Add(-d), format)
			if err != nil {
				return err
			}
			if out == "" || out == "-" {
				_, err = cmd.OutOrStdout().Write(b)
				return err
			}
			return os.WriteFile(out, b, 0o644)
		},
	}
	cmd.Flags().StringVar(&period, "period", "month", "day|week|month|quarter или 30d")
	cmd.Flags().StringVar(&format, "format", "md", "md|docx|pdf")
	cmd.Flags().StringVar(&out, "out", "-", "файл")
	cmd.Flags().StringVar(&org, "org", "", "org id")
	return cmd
}

func newIOCCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "ioc", Short: "Экспорт IOC (STIX 2.1 / MISP)"}
	var since, format string
	export := &cobra.Command{
		Use: "export",
		RunE: func(_ *cobra.Command, _ []string) error {
			d, err := config.ParseDuration(since)
			if err != nil {
				return err
			}
			st, _, err := openStore()
			if err != nil {
				return err
			}
			defer st.Close()
			_, err = report.ExportIOC(context.Background(), st, time.Now().Add(-d), format)
			return err
		},
	}
	export.Flags().StringVar(&since, "since", "30d", "период")
	export.Flags().StringVar(&format, "format", "stix", "stix|misp")
	cmd.AddCommand(export)
	return cmd
}

func newWeightsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "weights", Short: "Веса сигналов"}
	var labels, out string
	tune := &cobra.Command{
		Use: "tune", Short: "Калибровка весов по меткам аналитиков (TODO F-4.6.4)",
		RunE: func(_ *cobra.Command, _ []string) error {
			_ = labels
			_ = out
			return errNotImplemented
		},
	}
	tune.Flags().StringVar(&labels, "labels", "labels.jsonl", "метки")
	tune.Flags().StringVar(&out, "out", "weights.tuned.yaml", "результат")
	show := &cobra.Command{
		Use: "show", Short: "Активные веса",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, _, cancel, err := buildApp(app.Options{NoStore: true, NoLLM: true})
			if err != nil {
				return err
			}
			defer cancel()
			defer a.Close()
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(a.Score.Weights())
		},
	}
	cmd.AddCommand(tune, show)
	return cmd
}

func newKeygenCmd() *cobra.Command {
	return &cobra.Command{
		Use: "keygen", Short: "Сгенерировать ключ шифрования хранилища (hex, 32 байта) для PL_ENC_KEY",
		RunE: func(cmd *cobra.Command, _ []string) error {
			k, err := crypto.GenerateKey()
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), k)
			return nil
		},
	}
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func periodDuration(p string) (time.Duration, error) {
	switch p {
	case "day":
		return 24 * time.Hour, nil
	case "week":
		return 7 * 24 * time.Hour, nil
	case "month":
		return 30 * 24 * time.Hour, nil
	case "quarter":
		return 90 * 24 * time.Hour, nil
	}
	return config.ParseDuration(p)
}
