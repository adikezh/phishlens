package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/phishlens/phishlens/internal/domain"
)

func testIncidentSubmission() *domain.Submission {
	return &domain.Submission{
		ID: "sub-1", Message: &domain.ParsedMail{
			From:     domain.Address{Addr: "attacker@evil.example", Domain: "evil.example"},
			Links:    []domain.Link{{Href: "https://login.evil.example", Domain: "evil.example"}},
			TextBody: "private body must not leave PhishLens",
		},
		Result: &domain.Analysis{Verdict: domain.VerdictPhishing, Score: 91, Confidence: .94,
			Signals: []domain.Signal{{ID: "link.punycode"}}},
	}
}

func TestIRISCreatesPrivacySafeCase(t *testing.T) {
	var payload irisCase
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &payload))
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	err := NewIRIS(config.IRIS{APIURL: srv.URL, CustomerID: 7, MinVerdict: "suspicious"}, "iris-key").Notify(context.Background(), testIncidentSubmission())
	require.NoError(t, err)
	require.Equal(t, "Bearer iris-key", auth)
	require.Equal(t, 7, payload.CaseCustomer)
	require.Equal(t, "sub-1", payload.CaseSOCID)
	require.NotContains(t, payload.CaseDescription, "private body")
}

func TestJiraCreatesADFIssueAndSupportsBearer(t *testing.T) {
	var body map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &body))
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	err := NewJira(config.Jira{APIURL: srv.URL, ProjectKey: "SOC", IssueType: "Task", MinVerdict: "suspicious"}, "", "jira-token").Notify(context.Background(), testIncidentSubmission())
	require.NoError(t, err)
	require.Equal(t, "Bearer jira-token", auth)
	require.Equal(t, "SOC", body["fields"].(map[string]any)["project"].(map[string]any)["key"])
	description := body["fields"].(map[string]any)["description"].(map[string]any)
	encoded, _ := json.Marshal(description)
	require.True(t, strings.Contains(string(encoded), "sub-1"))
	require.NotContains(t, string(encoded), "private body")
}

func TestIncidentNotifiersSkipBelowThreshold(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()
	clean := testIncidentSubmission()
	clean.Result.Verdict = domain.VerdictClean
	require.NoError(t, NewIRIS(config.IRIS{APIURL: srv.URL, CustomerID: 1, MinVerdict: "suspicious"}, "key").Notify(context.Background(), clean))
	require.False(t, called)
}
