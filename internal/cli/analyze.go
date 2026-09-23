package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/phishlens/phishlens/internal/app"
	"github.com/phishlens/phishlens/internal/domain"
	"github.com/phishlens/phishlens/internal/httpapi"
)

func newAnalyzeCmd() *cobra.Command {
	var (
		file, text, image, lang string
		asJSON, noLLM, save     bool
	)
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Проанализировать письмо: --file x.eml | --text \"...\" | --image shot.png | stdin",
		RunE: func(cmd *cobra.Command, _ []string) error {
			req := app.Request{Channel: domain.ChannelCLI, Lang: lang, NoLLM: noLLM, NoStore: !save}
			switch {
			case file != "":
				data, err := os.ReadFile(file)
				if err != nil {
					return err
				}
				kind, err := httpapi.DetectKind(filepath.Base(file), "", data)
				if err != nil {
					return err
				}
				req.Kind, req.Data = kind, data
			case image != "":
				data, err := os.ReadFile(image)
				if err != nil {
					return err
				}
				req.Kind, req.Data = domain.KindImage, data
			case text != "":
				req.Kind, req.Data = domain.KindText, []byte(text)
			default:
				data, err := io.ReadAll(cmd.InOrStdin())
				if err != nil || len(strings.TrimSpace(string(data))) == 0 {
					return errors.New("nothing to analyze: pass --file, --text, --image or pipe input")
				}
				req.Kind, req.Data = domain.KindText, data
			}
			a, ctx, cancel, err := buildApp(app.Options{NoStore: !save, NoLLM: noLLM})
			if err != nil {
				return err
			}
			defer cancel()
			defer a.Close()
			sub, err := a.Analyzer.Analyze(ctx, req)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				enc.SetEscapeHTML(false)
				return enc.Encode(sub)
			}
			printHuman(cmd.OutOrStdout(), sub)
			return nil
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", ".eml / .msg / .txt")
	cmd.Flags().StringVarP(&text, "text", "t", "", "сырой текст письма")
	cmd.Flags().StringVar(&image, "image", "", "скриншот (png/jpg)")
	cmd.Flags().StringVar(&lang, "lang", "", "язык объяснений ru|en|kz")
	cmd.Flags().BoolVar(&asJSON, "json", false, "вывод JSON")
	cmd.Flags().BoolVar(&noLLM, "no-llm", false, "без LLM-объяснения")
	cmd.Flags().BoolVar(&save, "save", false, "сохранить в БД (по умолчанию CLI не пишет в хранилище)")
	return cmd
}

func printHuman(w io.Writer, sub *domain.Submission) {
	a := sub.Result
	fmt.Fprintf(w, "\n  %-12s %s   score %d/100   confidence %.0f%%   %s   %d ms\n", strings.ToUpper(string(a.Verdict)), verdictMark(a.Verdict), a.Score, a.Confidence*100, a.AttackType, a.DurationMs)
	if m := sub.Message; m != nil {
		fmt.Fprintf(w, "  from: %s   subject: %s\n", m.From, m.Subject)
		if m.AuthResults.Source != "" {
			fmt.Fprintf(w, "  auth: spf=%s dkim=%s dmarc=%s\n", m.AuthResults.SPF, m.AuthResults.DKIM, m.AuthResults.DMARC)
		}
	}
	if a.Brand != nil {
		fmt.Fprintf(w, "  brand: %s (%s, official=%v)\n", a.Brand.Name, a.Brand.Method, a.Brand.Official)
	}
	fmt.Fprintln(w)
	for _, s := range a.Signals {
		fmt.Fprintf(w, "  %+4d ×%.2f  %-32s %s\n", s.Weight, s.Confidence, s.ID, s.Explanation)
		if s.Evidence != "" {
			fmt.Fprintf(w, "               └ %s\n", s.Evidence)
		}
	}
	if a.LLM != nil {
		fmt.Fprintf(w, "\n  [ИИ-объяснение · %s/%s] %s\n", a.LLM.Provider, a.LLM.Model, a.LLM.Summary)
	}
	fmt.Fprintln(w)
	for _, r := range a.Recommendations {
		fmt.Fprintf(w, "  → %s\n", r)
	}
	for _, wrn := range a.Warnings {
		fmt.Fprintf(w, "  ! %s\n", wrn)
	}
	fmt.Fprintln(w)
}

func verdictMark(v domain.Verdict) string {
	switch v {
	case domain.VerdictPhishing:
		return "🟥"
	case domain.VerdictSuspicious:
		return "🟧"
	case domain.VerdictNeedsReview:
		return "🟪"
	default:
		return "🟩"
	}
}
