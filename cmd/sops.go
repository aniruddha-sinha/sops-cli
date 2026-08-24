package cmd

import (
	"fmt"

	"github.com/aniruddha-sinha/sops-cli/internal/sops"
	"github.com/spf13/cobra"
)

func newEncryptCmd() *cobra.Command {
	var inFile, outFile, keyType, keySpec, format string
	cmd := &cobra.Command{
		Use:     "encrypt",
		Aliases: []string{"e"},
		Short:   "encrypt JSON/YAML/BINARY secrets with master-key provider as AWSKMS, PGP",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := sops.ValidateFilePath(inFile); err != nil {
				return err
			}

			if err := sops.ValidateFilePath(outFile); err != nil {
				return err
			}

			if _, err := sops.ValidateFormatAndGetStore(format); err != nil {
				return err
			}

			if _, err := sops.ValidateKeyTypeAndGetMasterKey(keyType, keySpec); err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			encOut, err := sops.Encrypt(inFile, format, keyType, keySpec)
			if err != nil {
				return err
			}

			if outFile == "" {
				fmt.Println(encOut)
				return nil
			}

			return sops.Save(outFile, encOut)
		},
	}

	cmd.Flags().StringVar(&format, "format", "json", "the input file format : JSON/YAML/BINARY")
	cmd.Flags().StringVar(&keyType, "key-type", "", "Key Type: KMS, pgp")
	cmd.Flags().StringVar(&keySpec, "key", "", "key detail: KMS ARN, PGP FINGERPRINT")
	cmd.Flags().StringVar(&inFile, "in", "", "Input file path to encrypt")
	cmd.Flags().StringVar(&outFile, "out", "", "Output file (defaults to stdout)")

	for _, flag := range []string{"key-type", "key", "in", "format"} {
		if err := cmd.MarkFlagRequired(flag); err != nil {
			return nil
		}
	}

	return cmd
}
