package app

import (
	"context"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/phishlens/phishlens/internal/domain"
)

// TestOfflineTextPerformance is the executable form of the TЗ performance
// gate: no network, no LLM, and 50 simultaneous text analyses. Persistence is
// disabled so this measures the analysis pipeline rather than SQLite writes.
func TestOfflineTextPerformance(t *testing.T) {
	a := testApp(t)
	oldProcs := runtime.GOMAXPROCS(2)
	t.Cleanup(func() { runtime.GOMAXPROCS(oldProcs) })

	const workers = 50
	input := []byte("From: security@example.test\nSubject: срочно подтвердите доступ\n\nОткройте https://login.example.test и подтвердите код.")
	durations := make([]time.Duration, workers)
	errs := make(chan error, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			started := time.Now()
			_, err := a.Analyzer.Analyze(context.Background(), Request{Kind: domain.KindText, Data: input, NoStore: true})
			durations[i] = time.Since(started)
			if err != nil {
				errs <- err
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p95 := durations[(workers*95+99)/100-1]
	require.LessOrEqual(t, p95, 300*time.Millisecond,
		"TЗ offline text p95 gate exceeded: p95=%s max=%s", p95, durations[len(durations)-1])
}
