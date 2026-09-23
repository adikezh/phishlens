package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateRequiresTLSCertificatePair(t *testing.T) {
	cfg := Default()
	cfg.Server.TLS.CertFile = "server.crt"
	require.EqualError(t, cfg.Validate(), "config: server.tls.cert and server.tls.key must be configured together")

	cfg.Server.TLS.KeyFile = "server.key"
	require.NoError(t, cfg.Validate())
}
