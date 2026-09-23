package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/phishlens/phishlens/internal/config"
	"golang.org/x/oauth2"
)

const oidcCookie = "phishlens_oidc"

type oidcState struct {
	nonce   string
	expires time.Time
}

type oidcSession struct {
	Subject string `json:"sub"`
	Email   string `json:"email,omitempty"`
	Role    string `json:"role"`
	OrgID   string `json:"org_id,omitempty"`
	Expires int64  `json:"exp"`
}

type oidcAuth struct {
	cfg      config.OIDC
	provider *oidc.Provider
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	secret   []byte
	mu       sync.Mutex
	states   map[string]oidcState
}

func newOIDCAuth(ctx context.Context, cfg config.OIDC) (*oidcAuth, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	secret := os.Getenv(cfg.ClientSecretEnv)
	sessionSecret := os.Getenv(cfg.SessionSecretEnv)
	if secret == "" || len(sessionSecret) < 32 {
		return nil, errors.New("oidc: client secret or session secret is missing (session secret must be at least 32 bytes)")
	}
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery: %w", err)
	}
	oauth := oauth2.Config{ClientID: cfg.ClientID, ClientSecret: secret, Endpoint: provider.Endpoint(), RedirectURL: cfg.RedirectURL, Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
	return &oidcAuth{cfg: cfg, provider: provider, oauth: oauth, verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}), secret: []byte(sessionSecret), states: map[string]oidcState{}}, nil
}

func (a *oidcAuth) newState() (state, nonce string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	state = base64.RawURLEncoding.EncodeToString(b)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	nonce = base64.RawURLEncoding.EncodeToString(b)
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, v := range a.states {
		if now.After(v.expires) {
			delete(a.states, k)
		}
	}
	a.states[state] = oidcState{nonce: nonce, expires: now.Add(5 * time.Minute)}
	return state, nonce, nil
}

func (a *oidcAuth) takeState(state string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, ok := a.states[state]
	if ok {
		delete(a.states, state)
	}
	return v.nonce, ok && time.Now().Before(v.expires)
}

func (a *oidcAuth) signSession(s oidcSession) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(b)
	mac := hmac.New(sha256.New, a.secret)
	_, _ = mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (a *oidcAuth) verifySession(raw string) (oidcSession, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return oidcSession{}, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return oidcSession{}, false
	}
	mac := hmac.New(sha256.New, a.secret)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return oidcSession{}, false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return oidcSession{}, false
	}
	var s oidcSession
	if json.Unmarshal(b, &s) != nil || s.Subject == "" || s.Expires <= time.Now().Unix() {
		return oidcSession{}, false
	}
	return s, true
}

func (a *oidcAuth) session(r *http.Request) (Principal, bool) {
	c, err := r.Cookie(oidcCookie)
	if err != nil {
		return Principal{}, false
	}
	s, ok := a.verifySession(c.Value)
	if !ok {
		return Principal{}, false
	}
	return Principal{Role: s.Role, OrgID: s.OrgID, KeyID: "oidc:" + s.Subject, Name: s.Email}, true
}

func (a *oidcAuth) role(claims map[string]any) string {
	groups, _ := claims[a.cfg.GroupsClaim].([]any)
	for _, raw := range groups {
		group, _ := raw.(string)
		if group != "" && group == a.cfg.AdminGroup && a.cfg.AdminGroup != "" {
			return RoleAdmin
		}
	}
	for _, raw := range groups {
		group, _ := raw.(string)
		if group != "" && group == a.cfg.AnalystGroup && a.cfg.AnalystGroup != "" {
			return RoleAnalyst
		}
	}
	return RoleUser
}

func (a *oidcAuth) org(claims map[string]any) string {
	if v, ok := claims[a.cfg.OrgClaim].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func (a *oidcAuth) setCookie(w http.ResponseWriter, r *http.Request, value string) {
	https := r.TLS != nil || strings.HasPrefix(strings.ToLower(r.Header.Get("X-Forwarded-Proto")), "https")
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: value, Path: "/", HttpOnly: true, Secure: https, SameSite: http.SameSiteLaxMode, MaxAge: 8 * 60 * 60})
}

func (a *oidcAuth) clearCookie(w http.ResponseWriter, r *http.Request) {
	https := r.TLS != nil || strings.HasPrefix(strings.ToLower(r.Header.Get("X-Forwarded-Proto")), "https")
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: "/", HttpOnly: true, Secure: https, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.Error(w, "oidc is disabled", http.StatusNotFound)
		return
	}
	state, nonce, err := s.oidc.newState()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "oidc_error", "could not create login state")
		return
	}
	http.Redirect(w, r, s.oidc.oauth.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		http.Error(w, "oidc is disabled", http.StatusNotFound)
		return
	}
	state := r.URL.Query().Get("state")
	nonce, ok := s.oidc.takeState(state)
	if !ok {
		writeError(w, http.StatusBadRequest, "oidc_state", "invalid or expired login state")
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		writeError(w, http.StatusUnauthorized, "oidc_denied", "identity provider denied login")
		return
	}
	tok, err := s.oidc.oauth.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "oidc_exchange", "could not exchange authorization code")
		return
	}
	idTokenRaw, ok := tok.Extra("id_token").(string)
	if !ok || idTokenRaw == "" {
		writeError(w, http.StatusUnauthorized, "oidc_token", "identity provider did not return an id token")
		return
	}
	idToken, err := s.oidc.verifier.Verify(r.Context(), idTokenRaw)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "oidc_token", "invalid identity token")
		return
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil || claims["nonce"] != nonce {
		writeError(w, http.StatusUnauthorized, "oidc_nonce", "invalid identity token nonce")
		return
	}
	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	value, err := s.oidc.signSession(oidcSession{Subject: sub, Email: email, Role: s.oidc.role(claims), OrgID: s.oidc.org(claims), Expires: time.Now().Add(8 * time.Hour).Unix()})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "oidc_session", "could not create session")
		return
	}
	s.oidc.setCookie(w, r, value)
	http.Redirect(w, r, "/ui/queue", http.StatusFound)
}

func (s *Server) handleOIDCLogout(w http.ResponseWriter, r *http.Request) {
	if s.oidc != nil {
		s.oidc.clearCookie(w, r)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}
