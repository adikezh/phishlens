package reputation

// The in-memory TTL cache is in client.go. When an application store is
// attached, provider responses are also persisted in reputation_cache; a
// database failure still degrades to the bounded in-memory/unknown behavior.
