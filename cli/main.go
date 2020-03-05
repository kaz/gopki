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
			{
				Name:   "build-client-full",
				Action: buildClientFull,
			},
			{
				Name:   "build-server-full",
				Action: buildServerFull,
			},
			{
				Name:   "show-ca",
				Action: showCA,
			},
			{
				Name:   "show-cert",
				Action: showCert,
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

func buildClientFull(c *cli.Context) error {
	commonName := "client"
	if c.NArg() > 0 {
		commonName = c.Args().First()
	}

	if err := action.BuildClientFull(commonName, driver); err != nil {
		return fmt.Errorf("action.BuildClientFull failed: %w", err)
	}
	return nil
}

func buildServerFull(c *cli.Context) error {
	commonName := "server"
	if c.NArg() > 0 {
		commonName = c.Args().First()
	}

	if err := action.BuildServerFull(commonName, driver); err != nil {
		return fmt.Errorf("action.BuildServerFull failed: %w", err)
	}
	return nil
}

func showCA(c *cli.Context) error {
	cert, err := action.ShowCA(driver)
	if err != nil {
		return fmt.Errorf("action.ShowCA failed: %w", err)
	}

	fmt.Printf("%s", cert)
	return nil
}

func showCert(c *cli.Context) error {
	commonName := ""
	if c.NArg() > 0 {
		commonName = c.Args().First()
	}

	certs, err := action.ShowCert(commonName, driver)
	if err != nil {
		return fmt.Errorf("action.ShowCert failed: %w", err)
	}

	for _, cert := range certs {
		fmt.Printf("%s", cert)
	}
	return nil
}
