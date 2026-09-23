package reputation

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

var errCircuitOpen = errors.New("provider circuit is open")

// circuitBreaker is intentionally small: three consecutive provider failures
// open the circuit for cooldown, while a successful call closes it again.
// Unknown provider results never become positive reputation signals.
type circuitBreaker struct {
	mu        sync.Mutex
	failures  int
	opened    time.Time
	threshold int
	cooldown  time.Duration
}

func newCircuitBreaker(threshold int, cooldown time.Duration) *circuitBreaker {
	if threshold < 1 {
		threshold = 3
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &circuitBreaker{threshold: threshold, cooldown: cooldown}
}

func (b *circuitBreaker) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.opened.IsZero() || !now.Before(b.opened) {
		if !b.opened.IsZero() {
			b.opened = time.Time{}
			b.failures = 0
		}
		return true
	}
	return false
}

func (b *circuitBreaker) observe(now time.Time, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		b.failures = 0
		b.opened = time.Time{}
		return
	}
	b.failures++
	if b.failures >= b.threshold {
		b.opened = now.Add(b.cooldown)
	}
}

func (b *circuitBreaker) state(now time.Time) (failures int, opened bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failures, !b.opened.IsZero() && now.Before(b.opened)
}

func circuitError(provider string) error { return fmt.Errorf("%s: %w", provider, errCircuitOpen) }
