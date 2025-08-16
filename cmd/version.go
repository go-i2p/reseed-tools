package cmd

import (
	"fmt"

	"github.com/urfave/cli/v3"
	"i2pgit.org/go-i2p/reseed-tools/reseed"
)

// NewVersionCommand creates a new CLI command for displaying the reseed-tools version.
// This command provides version information for troubleshooting and compatibility checking
// with other I2P network components and reseed infrastructure.
func NewVersionCommand() *cli.Command {
	return &cli.Command{
		Name:  "version",
		Usage: "Print the version number of reseed-tools",
		Action: func(c *cli.Context) error {
			// Print the current version from reseed package constants
			fmt.Printf("%s\n", reseed.Version)
			return nil
		},
	}
}
