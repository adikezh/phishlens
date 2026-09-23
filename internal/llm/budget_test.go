package llm

import "testing"

func TestBudgetEnforcesHourlyCalls(t *testing.T) {
	b := newBudget(2, 0)
	p := pricing{inputUSDPer1K: 1, outputUSDPer1K: 1}
	r1 := b.estimateAndReserve(10, 10, p)
	r2 := b.estimateAndReserve(10, 10, p)
	r3 := b.estimateAndReserve(10, 10, p)
	if !r1.ok || !r2.ok || r3.ok {
		t.Fatalf("hourly reservations: r1=%+v r2=%+v r3=%+v", r1, r2, r3)
	}
	r1.cancel()
	if r := b.estimateAndReserve(10, 10, p); r.ok {
		t.Fatal("cancelled provider call must still consume hourly call capacity")
	}
}

func TestBudgetEnforcesDailyUSD(t *testing.T) {
	b := newBudget(10, 0.01)
	p := pricing{inputUSDPer1K: 1}
	first := b.estimateAndReserve(10, 0, p)
	second := b.estimateAndReserve(1, 0, p)
	if !first.ok || second.ok {
		t.Fatalf("daily reservations: first=%+v second=%+v", first, second)
	}
	first.settle(0.005)
	if r := b.estimateAndReserve(5, 0, p); !r.ok {
		t.Fatal("settling actual usage must release the unused estimate")
	}
}

func TestBudgetAllowsZeroPricedProvidersWithDailyCap(t *testing.T) {
	b := newBudget(0, 0.01)
	for i := 0; i < 100; i++ {
		if r := b.estimateAndReserve(100000, 1200, pricing{}); !r.ok {
			t.Fatalf("zero-priced provider was unexpectedly blocked at call %d", i)
		}
	}
}
