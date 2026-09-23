// Package migrations embeds SQL migrations in golang-migrate naming
// (NNNN_name.up.sql / NNNN_name.down.sql). Applied by internal/store.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
