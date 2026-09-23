package app

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/phishlens/phishlens/internal/netutil"
	"github.com/phishlens/phishlens/internal/store"
)

// storeLists adapts store.Store to signals.ListLookup (R-03). Entries are matched
// as exact address, exact host, or registrable domain; results are cached briefly.
type storeLists struct {
	st  store.Store
	org string
}

var listCache = struct {
	sync.Mutex
	items map[string]listCacheItem
}{items: map[string]listCacheItem{}}

type listCacheItem struct {
	values map[string]bool
	exp    time.Time
}

func (l *storeLists) load(ctx context.Context, kind store.ListKind) map[string]bool {
	key := l.org + "|" + string(kind)
	listCache.Lock()
	if it, ok := listCache.items[key]; ok && time.Now().Before(it.exp) {
		listCache.Unlock()
		return it.values
	}
	listCache.Unlock()
	entries, err := l.st.ListEntries(ctx, l.org, kind)
	values := map[string]bool{}
	if err == nil {
		for _, e := range entries {
			values[strings.ToLower(e.Value)] = true
		}
	}
	listCache.Lock()
	listCache.items[key] = listCacheItem{values: values, exp: time.Now().Add(30 * time.Second)}
	listCache.Unlock()
	return values
}

func (l *storeLists) match(ctx context.Context, kind store.ListKind, v string) (bool, string) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return false, ""
	}
	values := l.load(ctx, kind)
	if len(values) == 0 {
		return false, ""
	}
	if values[v] {
		return true, v
	}
	host := v
	if i := strings.LastIndex(v, "@"); i >= 0 {
		host = v[i+1:]
	}
	if values[host] {
		return true, host
	}
	if reg := netutil.RegistrableDomain(host); reg != "" && values[reg] {
		return true, reg
	}
	return false, ""
}

// IsAllowed implements signals.ListLookup.
func (l *storeLists) IsAllowed(ctx context.Context, v string) (bool, string) {
	return l.match(ctx, store.ListAllow, v)
}

// IsBlocked implements signals.ListLookup.
func (l *storeLists) IsBlocked(ctx context.Context, v string) (bool, string) {
	return l.match(ctx, store.ListBlock, v)
}

// InvalidateListCache drops cached lists after an edit.
func InvalidateListCache() {
	listCache.Lock()
	listCache.items = map[string]listCacheItem{}
	listCache.Unlock()
}
