package httpapi

import (
	"testing"
	"time"

	"github.com/phishlens/phishlens/internal/config"
	"github.com/stretchr/testify/require"
)

func testOIDCAuth() *oidcAuth {
	return &oidcAuth{cfg: config.OIDC{GroupsClaim: "groups", AnalystGroup: "analysts", AdminGroup: "admins", OrgClaim: "org_id"}, secret: []byte("01234567890123456789012345678901"), states: map[string]oidcState{}}
}

func TestOIDCSessionIsSignedAndExpires(t *testing.T) {
	a := testOIDCAuth()
	raw, err := a.signSession(oidcSession{Subject: "subject-1", Email: "analyst@example.test", Role: RoleAnalyst, OrgID: "org-1", Expires: time.Now().Add(time.Hour).Unix()})
	require.NoError(t, err)
	s, ok := a.verifySession(raw)
	require.True(t, ok)
	require.Equal(t, "subject-1", s.Subject)
	require.False(t, func() bool { _, ok := a.verifySession(raw+"x"); return ok }())
	_, ok = a.verifySession(mustOIDCSession(t, a, oidcSession{Subject: "expired", Expires: time.Now().Add(-time.Minute).Unix()}))
	require.False(t, ok)
}

func TestOIDCStateIsSingleUseAndExpires(t *testing.T) {
	a := testOIDCAuth()
	state, nonce, err := a.newState()
	require.NoError(t, err)
	require.NotEmpty(t, state)
	require.NotEmpty(t, nonce)
	taken, ok := a.takeState(state)
	require.True(t, ok)
	require.Equal(t, nonce, taken)
	_, ok = a.takeState(state)
	require.False(t, ok)
}

func TestOIDCRoleMappingDefaultsToUser(t *testing.T) {
	a := testOIDCAuth()
	require.Equal(t, RoleUser, a.role(map[string]any{"groups": []any{"other"}}))
	require.Equal(t, RoleAnalyst, a.role(map[string]any{"groups": []any{"analysts"}}))
	require.Equal(t, RoleAdmin, a.role(map[string]any{"groups": []any{"analysts", "admins"}}))
	require.Equal(t, "org-7", a.org(map[string]any{"org_id": "org-7"}))
}

func mustOIDCSession(t *testing.T, a *oidcAuth, s oidcSession) string {
	t.Helper()
	raw, err := a.signSession(s)
	require.NoError(t, err)
	return raw
}
