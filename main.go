package main

import (
	"context"
	"os"
	"runtime"

	"github.com/go-i2p/logger"
	"github.com/urfave/cli/v3"
	"i2pgit.org/go-i2p/reseed-tools/cmd"
	"i2pgit.org/go-i2p/reseed-tools/reseed"
)

var lgr = logger.GetGoI2PLogger()

func main() {
	// use at most half the cpu cores, but at least 1 core on single-core systems
	runtime.GOMAXPROCS(max(runtime.NumCPU()/2, 1))

	app := &cli.Command{
		Name:    "reseed-tools",
		Version: reseed.Version,
		Usage:   "I2P tools and reseed server",
		Authors: []any{
			"go-i2p <hankhill19580@gmail.com>",
		},
		Commands: []*cli.Command{
			cmd.NewReseedCommand(),
			cmd.NewSu3VerifyCommand(),
			cmd.NewKeygenCommand(),
			cmd.NewShareCommand(),
			cmd.NewDiagnoseCommand(),
			cmd.NewVersionCommand(),
			// cmd.NewSu3VerifyPublicCommand(),
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		lgr.WithError(err).Error("Application execution failed")
		os.Exit(1)
	}
}
