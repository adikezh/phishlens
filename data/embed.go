// Package data embeds reference lists shipped with the binary: brands, weights,
// keyword dictionaries, shorteners, risky TLDs, homoglyph table and demo emails.
// Files on disk (analysis.data_dir) override the embedded copies.
package data

import "embed"

//go:embed *.yaml *.txt keywords/*.yaml demo/*.eml
var FS embed.FS
