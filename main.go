/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	"os"

	"github.com/aniruddha-sinha/sops-cli/cmd"
)

func main() {
	if err := cmd.NewSopsCLICommand().Execute(); err != nil {
		os.Exit(1)
	}
}
