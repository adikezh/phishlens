// Package addins embeds the Outlook add-in static bundle (served at /addins/) and
// the Gmail Apps Script sources (for reference / docs).
package addins

import "embed"

//go:embed outlook/* gmail/*
var FS embed.FS
