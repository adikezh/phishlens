package app

import "github.com/phishlens/phishlens/internal/store"

func storeEntry(kind, value string) store.ListEntry {
	return store.ListEntry{Kind: store.ListKind(kind), Value: value, CreatedBy: "test"}
}
