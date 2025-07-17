package main

import (
	"os"
	"runtime"

	"github.com/go-i2p/logger"
	"github.com/urfave/cli/v3"
	"i2pgit.org/idk/reseed-tools/cmd"
	"i2pgit.org/idk/reseed-tools/reseed"
)

var lgr = logger.GetGoI2PLogger()

func main() {
	// TLS 1.3 is available only on an opt-in basis in Go 1.12.
	// To enable it, set the GODEBUG environment variable (comma-separated key=value options) such that it includes "tls13=1".
	// To enable it from within the process, set the environment variable before any use of TLS:
	os.Setenv("GODEBUG", os.Getenv("GODEBUG")+",tls13=1")

	// use at most half the cpu cores
	runtime.GOMAXPROCS(runtime.NumCPU() / 2)

	app := cli.NewApp()
	app.Name = "reseed-tools"
	app.Version = reseed.Version
	app.Usage = "I2P tools and reseed server"
	auth := &cli.Author{
		Name:  "go-i2p",
		Email: "hankhill19580@gmail.com",
	}
	app.Authors = append(app.Authors, auth)
	app.Flags = []cli.Flag{}
	app.Commands = []*cli.Command{
		cmd.NewReseedCommand(),
		cmd.NewSu3VerifyCommand(),
		cmd.NewKeygenCommand(),
		cmd.NewShareCommand(),
		cmd.NewVersionCommand(),
		// cmd.NewSu3VerifyPublicCommand(),
	}

	if err := app.Run(os.Args); err != nil {
		lgr.WithError(err).Error("Application execution failed")
		os.Exit(1)
	}
}
