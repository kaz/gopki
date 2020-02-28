package main

import (
	"fmt"
	"os"

	"github.com/kaz/gopki/action"
	"github.com/kaz/gopki/storage/local"
	"github.com/urfave/cli/v2"
)

var (
	driver = local.NewDriver("store.json")
)

func main() {
	app := &cli.App{
		Name:  "gopki",
		Usage: "Serverless Certificate Authority",

		Commands: []*cli.Command{
			{
				Name:   "build-ca",
				Action: buildCA,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(-1)
	}
}

func buildCA(c *cli.Context) error {
	commonName := "gopki Root CA"
	if c.NArg() > 0 {
		commonName = c.Args().First()
	}

	if err := action.BuildCA(commonName, driver); err != nil {
		return fmt.Errorf("action.BuildCA failed: %w", err)
	}
	return nil
}
