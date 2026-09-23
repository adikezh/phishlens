// Command phishlens is the single binary: server, CLI analysis and admin tools (ТЗ §9).
package main

import (
	"os"

	"github.com/phishlens/phishlens/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
