package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/kaz/gopki/agent"
	"github.com/kaz/gopki/keyfactory"
	"github.com/kaz/gopki/storage/local"
	"github.com/urfave/cli/v2"
)

var (
	cliAgent = agent.New(local.NewDriver("store.json"), keyfactory.Default())
)

func main() {
	app := &cli.App{
		Name:  "gopki",
		Usage: "Serverless Certificate Authority",

		Commands: []*cli.Command{
			{
				Name:   "import-ca",
				Action: importCA,
			},
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

func importCA(c *cli.Context) error {
	if c.NArg() != 2 {
		return fmt.Errorf("unexpected args number: %v", c.NArg())
	}

	certFile, err := os.Open(c.Args().Get(0))
	if err != nil {
		return fmt.Errorf("os.Open failed: %w", err)
	}
	defer certFile.Close()

	keyFile, err := os.Open(c.Args().Get(1))
	if err != nil {
		return fmt.Errorf("os.Open failed: %w", err)
	}
	defer keyFile.Close()

	cert, err := ioutil.ReadAll(certFile)
	if err != nil {
		return fmt.Errorf("ioutil.ReadAll failed: %w", err)
	}

	key, err := ioutil.ReadAll(keyFile)
	if err != nil {
		return fmt.Errorf("ioutil.ReadAll failed: %w", err)
	}

	if err := cliAgent.ImportCA(cert, key); err != nil {
		return fmt.Errorf("cliAgent.ImportCA failed: %w", err)
	}
	return nil
}

func buildCA(c *cli.Context) error {
	commonName := "gopki Root CA"
	if c.NArg() > 0 {
		commonName = c.Args().First()
	}

	if err := cliAgent.BuildCA(commonName); err != nil {
		return fmt.Errorf("cliAgent.BuildCA failed: %w", err)
	}
	return nil
}

func buildClientFull(c *cli.Context) error {
	commonName := "client"
	if c.NArg() > 0 {
		commonName = c.Args().First()
	}

	if err := cliAgent.BuildClientFull(commonName); err != nil {
		return fmt.Errorf("cliAgent.BuildClientFull failed: %w", err)
	}
	return nil
}

func buildServerFull(c *cli.Context) error {
	commonName := "server"
	if c.NArg() > 0 {
		commonName = c.Args().First()
	}

	if err := cliAgent.BuildServerFull(commonName); err != nil {
		return fmt.Errorf("cliAgent.BuildServerFull failed: %w", err)
	}
	return nil
}

func showCA(c *cli.Context) error {
	cert, err := cliAgent.ShowCA()
	if err != nil {
		return fmt.Errorf("cliAgent.ShowCA failed: %w", err)
	}

	fmt.Printf("%s", cert)
	return nil
}

func showCert(c *cli.Context) error {
	commonName := ""
	if c.NArg() > 0 {
		commonName = c.Args().First()
	}

	certs, err := cliAgent.ShowCert(commonName)
	if err != nil {
		return fmt.Errorf("cliAgent.ShowCert failed: %w", err)
	}

	for _, cert := range certs {
		fmt.Printf("%s", cert)
	}
	return nil
}
