package web

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/phishlens/phishlens/internal/app"
)

func TestTemplatesParse(t *testing.T) {
	if _, err := New(&app.App{Log: zerolog.Nop()}); err != nil {
		t.Fatalf("parse embedded templates: %v", err)
	}
}

func TestLandingRoute(t *testing.T) {
	u, err := New(&app.App{Log: zerolog.Nop()})
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	u.Routes(r)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest("GET", "/landing", nil))
	if resp.Code != 200 {
		t.Fatalf("landing status = %d", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "PhishLens") {
		t.Fatal("landing page does not contain product name")
	}
}
