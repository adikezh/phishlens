package reputation

// The in-memory TTL cache is in client.go. Persistent backing in the
// reputation_cache table remains an operational enhancement; callers still
// receive bounded, fail-closed-to-unknown behavior after a restart.
