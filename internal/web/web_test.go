package web

import (
	"testing"

	"github.com/rs/zerolog"

	"github.com/phishlens/phishlens/internal/app"
)

func TestTemplatesParse(t *testing.T) {
	if _, err := New(&app.App{Log: zerolog.Nop()}); err != nil {
		t.Fatalf("parse embedded templates: %v", err)
	}
}
