# Performance acceptance

The executable offline gate is `internal/app/performance_test.go`:

```powershell
go test ./internal/app -run TestOfflineTextPerformance -count=1 -v
```

It runs 50 simultaneous text analyses with `GOMAXPROCS=2`, disables network
providers and persistence, and fails when the p95 duration exceeds 300 ms. The
test performs one warm-up analysis and measures the deterministic steady-state
pipeline only; DNS/TI/LLM latency and database write capacity require separate
deployment-specific measurements.

The same gate should also be run with the race detector before a release:

```powershell
go test -race ./internal/app -run TestOfflineTextPerformance -count=1
```
