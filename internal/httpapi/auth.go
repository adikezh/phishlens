package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/phishlens/phishlens/internal/store"
)

// Roles (F-4.7.4).
const (
	RoleAnonymous = "anonymous"
	RoleUser      = "user"
	RoleAnalyst   = "analyst"
	RoleAdmin     = "admin"
)

// Principal is the authenticated caller.
type Principal struct {
	Role  string
	OrgID string
	KeyID string
	Name  string
}

type ctxKey int

const principalKey ctxKey = 1

// PrincipalFrom returns the caller from context.
func PrincipalFrom(ctx context.Context) Principal {
	if p, ok := ctx.Value(principalKey).(Principal); ok {
		return p
	}
	return Principal{Role: RoleAnonymous}
}

// HashKey returns the sha256 hex of an API key (what the DB stores).
func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// GenerateKey returns a new random API key "pl_<base64url>".
func GenerateKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "pl_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func extractKey(r *http.Request) string {
	if k := r.Header.Get("X-API-Key"); k != "" {
		return k
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// authenticate resolves an API key or an OIDC session to a Principal; anonymous
// callers pass through with RoleAnonymous and are gated per-route.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := Principal{Role: RoleAnonymous}
		key := extractKey(r)
		if key != "" {
			if !s.app.Cfg.Auth.APIKeysEnabled || s.app.Store == nil {
				writeError(w, http.StatusUnauthorized, "unauthorized", "api keys are disabled")
				return
			}
			k, err := s.app.Store.GetAPIKeyByHash(r.Context(), HashKey(key))
			if err != nil || k.RevokedAt != nil {
				if err != nil && !errors.Is(err, store.ErrNotFound) {
					s.log.Error().Err(err).Msg("api key lookup")
				}
				writeError(w, http.StatusUnauthorized, "unauthorized", "invalid api key")
				return
			}
			p = Principal{Role: k.Role, OrgID: k.OrgID, KeyID: k.ID, Name: k.Name}
		} else if s.oidc != nil {
			if sessionPrincipal, ok := s.oidc.session(r); ok {
				p = sessionPrincipal
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	})
}

// allowAnonymous permits unauthenticated calls only when auth.anonymous_analyze is on.
func (s *Server) allowAnonymous(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if PrincipalFrom(r.Context()).Role == RoleAnonymous && !s.app.Cfg.Auth.AnonymousAnalyze {
			writeError(w, http.StatusUnauthorized, "unauthorized", "api key required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := map[string]bool{}
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := PrincipalFrom(r.Context())
			if p.Role == RoleAnonymous {
				writeError(w, http.StatusUnauthorized, "unauthorized", "api key required")
				return
			}
			if !allowed[p.Role] {
				writeError(w, http.StatusForbidden, "forbidden", "insufficient role")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ---- rate limiting (per key or IP) -----------------------------------------

type rateLimiter struct {
	mu       sync.Mutex
	rps      float64
	limiters map[string]*entry
}

type entry struct {
	lim  *rate.Limiter
	seen time.Time
}

func newRateLimiter(rps float64) *rateLimiter {
	return &rateLimiter{rps: rps, limiters: map[string]*entry{}}
}

func (rl *rateLimiter) get(key string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if len(rl.limiters) > 10000 {
		cutoff := time.Now().Add(-10 * time.Minute)
		for k, e := range rl.limiters {
			if e.seen.Before(cutoff) {
				delete(rl.limiters, k)
			}
		}
	}
	e, ok := rl.limiters[key]
	if !ok {
		e = &entry{lim: rate.NewLimiter(rate.Limit(rl.rps), int(rl.rps*4)+1)}
		rl.limiters[key] = e
	}
	e.seen = time.Now()
	return e.lim
}

func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.limiter.rps <= 0 {
			next.ServeHTTP(w, r)
			return
		}
		key := PrincipalFrom(r.Context()).KeyID
		if key == "" {
			key = "ip:" + r.RemoteAddr
		}
		if !s.limiter.get(key).Allow() {
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}
