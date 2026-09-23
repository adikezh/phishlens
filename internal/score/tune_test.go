package score

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTuneMovesSignalTowardAnalystLabels(t *testing.T) {
	base := &Weights{Thresholds: DefaultThresholds, Signals: map[string]int{"content.credential_request": 20, "content.urgency": 10}}
	labels := strings.NewReader(`{"label":"phishing","signals":{"content.credential_request":1}}` + "\n" +
		`{"label":"clean","signals":{"content.urgency":1}}` + "\n")
	got, count, err := Tune(labels, base)
	require.NoError(t, err)
	require.Equal(t, 2, count)
	require.Equal(t, base.Thresholds, got.Thresholds)
	require.Greater(t, got.Signals["content.credential_request"], 20)
}

func TestTuneRejectsInvalidLabels(t *testing.T) {
	base := &Weights{Signals: map[string]int{"x": 10}}
	_, _, err := Tune(strings.NewReader(`{"label":"unknown","signals":{"x":1}}`), base)
	require.Error(t, err)
	_, _, err = Tune(strings.NewReader(`{"label":"clean","signals":{"x":2}}`), base)
	require.Error(t, err)
}
