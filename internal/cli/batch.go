package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/phishlens/phishlens/internal/app"
	"github.com/phishlens/phishlens/internal/domain"
)

// batchResult is one JSONL line of `phishlens batch`.
type batchResult struct {
	File       string            `json:"file"`
	Verdict    domain.Verdict    `json:"verdict"`
	Score      int               `json:"score"`
	AttackType domain.AttackType `json:"attack_type"`
	Brand      string            `json:"brand,omitempty"`
	Signals    []string          `json:"signals"`
	DurationMs int               `json:"duration_ms"`
	Error      string            `json:"error,omitempty"`
}

// expected is testdata/expected/<name>.json.
type expected struct {
	Verdict    domain.Verdict `json:"verdict"`
	AttackType string         `json:"attack_type,omitempty"`
	MinScore   int            `json:"min_score,omitempty"`
	MaxScore   int            `json:"max_score,omitempty"`
	Signals    []string       `json:"signals,omitempty"` // must be present
}

func runCorpus(a *app.App, dir string, noLLM bool) ([]batchResult, error) {
	var files []string
	for _, pat := range []string{"*.eml", "*.txt", "*.msg"} {
		m, _ := filepath.Glob(filepath.Join(dir, pat))
		files = append(files, m...)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no .eml/.txt/.msg files in %s", dir)
	}
	var out []batchResult
	for _, f := range files {
		res := batchResult{File: filepath.Base(f)}
		data, err := os.ReadFile(f)
		if err != nil {
			res.Error = err.Error()
			out = append(out, res)
			continue
		}
		kind := domain.KindEML
		switch strings.ToLower(filepath.Ext(f)) {
		case ".txt":
			kind = domain.KindText
		case ".msg":
			kind = domain.KindMSG
		}
		sub, err := a.Analyzer.Analyze(a.Log.WithContext(contextBackground()), app.Request{Channel: domain.ChannelCLI, Kind: kind, Data: data, NoLLM: noLLM, NoStore: true})
		if err != nil {
			res.Error = err.Error()
			out = append(out, res)
			continue
		}
		r := sub.Result
		res.Verdict, res.Score, res.AttackType, res.DurationMs = r.Verdict, r.Score, r.AttackType, r.DurationMs
		if r.Brand != nil {
			res.Brand = r.Brand.Name
		}
		for _, s := range r.Signals {
			res.Signals = append(res.Signals, s.ID)
		}
		out = append(out, res)
	}
	return out, nil
}

func newBatchCmd() *cobra.Command {
	var dir, out string
	var noLLM, online bool
	cmd := &cobra.Command{
		Use:   "batch",
		Short: "Прогнать каталог писем и записать results.jsonl",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, _, cancel, err := buildApp(app.Options{NoStore: true, NoLLM: noLLM, Offline: !online})
			if err != nil {
				return err
			}
			defer cancel()
			defer a.Close()
			results, err := runCorpus(a, dir, noLLM)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if out != "" && out != "-" {
				f, err := os.Create(out)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}
			enc := json.NewEncoder(w)
			enc.SetEscapeHTML(false)
			for _, r := range results {
				if err := enc.Encode(r); err != nil {
					return err
				}
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "%d files processed\n", len(results))
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "testdata/eml", "каталог с письмами")
	cmd.Flags().StringVar(&out, "out", "-", "файл results.jsonl (- = stdout)")
	cmd.Flags().BoolVar(&noLLM, "no-llm", true, "без LLM")
	cmd.Flags().BoolVar(&online, "online", false, "включить сетевые проверки репутации (DNSBL/TI/RDAP)")
	return cmd
}

func newEvalCmd() *cobra.Command {
	var dir, expectedDir string
	var noLLM, online bool
	var minF1 float64
	cmd := &cobra.Command{
		Use:   "eval",
		Short: "Precision/recall/F1 по золотым вердиктам (testdata/expected/<file>.json)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, _, cancel, err := buildApp(app.Options{NoStore: true, NoLLM: noLLM, Offline: !online})
			if err != nil {
				return err
			}
			defer cancel()
			defer a.Close()
			results, err := runCorpus(a, dir, noLLM)
			if err != nil {
				return err
			}
			type counts struct{ tp, fp, fn int }
			perClass := map[domain.Verdict]*counts{}
			for _, v := range []domain.Verdict{domain.VerdictPhishing, domain.VerdictSuspicious, domain.VerdictClean, domain.VerdictNeedsReview} {
				perClass[v] = &counts{}
			}
			evaluated, correct := 0, 0
			w := cmd.OutOrStdout()
			for _, r := range results {
				name := strings.TrimSuffix(r.File, filepath.Ext(r.File))
				raw, err := os.ReadFile(filepath.Join(expectedDir, name+".json"))
				if err != nil {
					fmt.Fprintf(w, "  ?  %-32s %-12s %3d  (no expected file)\n", r.File, r.Verdict, r.Score)
					continue
				}
				var exp expected
				if err := json.Unmarshal(raw, &exp); err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				evaluated++
				ok := r.Verdict == exp.Verdict && r.Error == ""
				if exp.MinScore > 0 && r.Score < exp.MinScore {
					ok = false
				}
				if exp.MaxScore > 0 && r.Score > exp.MaxScore {
					ok = false
				}
				for _, want := range exp.Signals {
					if !contains(r.Signals, want) {
						ok = false
						fmt.Fprintf(w, "     missing signal %s\n", want)
					}
				}
				mark := "ok "
				if ok {
					correct++
					perClass[exp.Verdict].tp++
				} else {
					mark = "FAIL"
					perClass[exp.Verdict].fn++
					if c, has := perClass[r.Verdict]; has {
						c.fp++
					}
				}
				fmt.Fprintf(w, "  %s %-32s got %-12s %3d  want %-12s %s\n", mark, r.File, r.Verdict, r.Score, exp.Verdict, r.Error)
			}
			if evaluated == 0 {
				return fmt.Errorf("no expected files found in %s", expectedDir)
			}
			var macroF1 float64
			classes := 0
			fmt.Fprintln(w)
			for _, v := range []domain.Verdict{domain.VerdictPhishing, domain.VerdictSuspicious, domain.VerdictClean, domain.VerdictNeedsReview} {
				c := perClass[v]
				if c.tp+c.fn == 0 {
					continue
				}
				p := safeDiv(c.tp, c.tp+c.fp)
				rc := safeDiv(c.tp, c.tp+c.fn)
				f1 := 0.0
				if p+rc > 0 {
					f1 = 2 * p * rc / (p + rc)
				}
				macroF1 += f1
				classes++
				fmt.Fprintf(w, "  %-12s precision %.2f  recall %.2f  f1 %.2f  (n=%d)\n", v, p, rc, f1, c.tp+c.fn)
			}
			if classes > 0 {
				macroF1 /= float64(classes)
			}
			acc := float64(correct) / float64(evaluated)
			fmt.Fprintf(w, "\n  accuracy %.2f  macro-F1 %.2f  (%d/%d)\n", acc, macroF1, correct, evaluated)
			if minF1 > 0 && macroF1 < minF1 {
				return fmt.Errorf("macro-F1 %.2f below threshold %.2f", macroF1, minF1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "testdata/eml", "каталог с письмами")
	cmd.Flags().StringVar(&expectedDir, "expected", "testdata/expected", "каталог золотых вердиктов")
	cmd.Flags().BoolVar(&noLLM, "no-llm", true, "без LLM")
	cmd.Flags().Float64Var(&minF1, "min-f1", 0, "порог macro-F1 для CI (0 = не проверять)")
	cmd.Flags().BoolVar(&online, "online", false, "включить сетевые проверки репутации (DNSBL/TI/RDAP)")
	return cmd
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func safeDiv(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}
