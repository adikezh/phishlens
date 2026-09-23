// Package prompts embeds LLM prompt templates. Files on disk (analysis.prompts_dir) override.
package prompts

import "embed"

//go:embed *.txt
var FS embed.FS
