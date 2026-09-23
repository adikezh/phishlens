package signals_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phishlens/phishlens/internal/signals/all"
)

// Every registered deterministic/semantic check must have a reviewable page
// in the repository, as required by TZ §4.2 and the Definition of Done.
func TestRegisteredSignalsHaveDocumentation(t *testing.T) {
	docsDir := filepath.Join("..", "..", "docs", "signals")
	for _, check := range all.New().Checks() {
		path := filepath.Join(docsDir, check.ID()+".md")
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("signal %s has no documentation at %s: %v", check.ID(), path, err)
		}
		if !strings.Contains(string(body), check.ID()) {
			t.Fatalf("signal %s documentation does not name the signal", check.ID())
		}
	}
}
