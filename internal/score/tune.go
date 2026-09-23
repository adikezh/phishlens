package score

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"
)

// LabelExample is the JSONL contract consumed by weights tune.
// Label is phishing, suspicious, or clean; Signals maps signal IDs to their
// observed confidence in the reviewed submission.
type LabelExample struct {
	Label   string             `json:"label"`
	Signals map[string]float64 `json:"signals"`
}

// Tune learns signal weights from analyst labels using bounded ridge gradient
// descent. Existing weights are the prior, so sparse labels do not erase
// signals that are not present in the calibration sample.
func Tune(r io.Reader, base *Weights) (*Weights, int, error) {
	if base == nil {
		return nil, 0, fmt.Errorf("weights: base weights are required")
	}
	examples, err := readLabels(r)
	if err != nil {
		return nil, 0, err
	}
	if len(examples) == 0 {
		return nil, 0, fmt.Errorf("weights: no labels found")
	}

	out := base.Merge(nil, nil)
	keys := make(map[string]struct{}, len(out.Signals))
	values := make(map[string]float64, len(out.Signals))
	for id := range out.Signals {
		keys[id] = struct{}{}
		values[id] = float64(out.Signals[id])
	}
	for _, ex := range examples {
		for id := range ex.Signals {
			keys[id] = struct{}{}
			if _, ok := out.Signals[id]; !ok {
				out.Signals[id] = 0
				values[id] = 0
			}
		}
	}

	const (
		learningRate = 0.002
		regularizer  = 0.0005
		epochs       = 2500
	)
	for epoch := 0; epoch < epochs; epoch++ {
		grad := make(map[string]float64, len(keys))
		for _, ex := range examples {
			prediction := 0.0
			for id, confidence := range ex.Signals {
				prediction += values[id] * confidence
			}
			errScore := prediction - ex.target
			for id, confidence := range ex.Signals {
				grad[id] += errScore*confidence + regularizer*(values[id]-float64(base.Signals[id]))
			}
		}
		for id := range keys {
			values[id] -= learningRate * grad[id] / float64(len(examples))
		}
	}
	for id := range keys {
		out.Signals[id] = clampWeight(values[id])
	}
	return out, len(examples), nil
}

func clampWeight(v float64) int {
	if v > 100 {
		v = 100
	}
	if v < -100 {
		v = -100
	}
	return int(math.Round(v))
}

type parsedLabel struct {
	target  float64
	Signals map[string]float64
}

func readLabels(r io.Reader) ([]parsedLabel, error) {
	s := bufio.NewScanner(r)
	labels := make([]parsedLabel, 0)
	line := 0
	for s.Scan() {
		line++
		if strings.TrimSpace(s.Text()) == "" {
			continue
		}
		var raw LabelExample
		if err := json.Unmarshal(s.Bytes(), &raw); err != nil {
			return nil, fmt.Errorf("weights: labels line %d: %w", line, err)
		}
		raw.Label = strings.ToLower(strings.TrimSpace(raw.Label))
		var target float64
		switch raw.Label {
		case "phishing", "phish", "confirmed_phish":
			target = 100
		case "suspicious", "review":
			target = 50
		case "clean", "confirmed_clean":
			target = 0
		default:
			return nil, fmt.Errorf("weights: labels line %d: label must be phishing, suspicious, or clean", line)
		}
		if len(raw.Signals) == 0 {
			return nil, fmt.Errorf("weights: labels line %d: signals are required", line)
		}
		for id, confidence := range raw.Signals {
			if strings.TrimSpace(id) == "" || confidence < 0 || confidence > 1 || math.IsNaN(confidence) {
				return nil, fmt.Errorf("weights: labels line %d: invalid signal confidence", line)
			}
		}
		labels = append(labels, parsedLabel{target: target, Signals: raw.Signals})
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("weights: read labels: %w", err)
	}
	return labels, nil
}
