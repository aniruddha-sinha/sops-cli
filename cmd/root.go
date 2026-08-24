package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

func NewSopsCLICommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "sops-cli",
		Short:        "encrypt/decrypt your JSON/YAML/BIN secrets on the go",
		SilenceUsage: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if os.Geteuid() == 0 {
				log.Println("Warning /!\\ : running sops-cli as root can be dangerous")
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			if err := cmd.Help(); err != nil {
				fmt.Print(err)
			}
		},
	}

	// cobra.OnInitialize ensures the config is only loaded when a command actually runs,
	// preventing disk writes during simple tasks like 'sops-cli --help'
	cobra.OnInitialize(func() {})

	cmd.AddCommand(
		newEncryptCmd(),
	)

	cmd.SetOut(os.Stdout)
	cmd.SetErr(os.Stderr)

	return cmd
}
