package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func newEncryptCmd() *cobra.Command {
	var inFileFormat, keyType, keyDetail, inputFilePath, outputFilePath string
	cmd := &cobra.Command{
		Use:     "encrypt",
		Aliases: []string{"e"},
		Short:   "encrypt JSON/YAML/BIN secrets with masterkey provider as AWSKMS, GCPKMS, PGP",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			inputFileFormat := strings.ToLower(inFileFormat)
			switch inputFileFormat {
			case "json", "yaml", "binary":
			default:
				return fmt.Errorf("invalid input file format %s, must be one of json yaml binary ", inputFileFormat)

			}

			kType := strings.ToLower(keyType)
			switch kType {
			case "awskms", "gcpkms", "pgp":
			default:
				return fmt.Errorf("invalid key type %s, must be one of awskms gcpkms pgp ", inputFileFormat)
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	cmd.Flags().StringVar(&inFileFormat, "format", "json", "File Format : JSON/YAML/BIN")
	cmd.Flags().StringVar(&keyType, "key-type", "", "Key Type: awskms, gcpkms, pgp")
	cmd.Flags().StringVar(&keyDetail, "key", "", "key detail: AWS KMS ARN, GCP KMS RESOURCE ID, PGP FINGERPRINT")
	cmd.Flags().StringVar(&inputFilePath, "in", "", "Input file path to encrypt")
	cmd.Flags().StringVar(&outputFilePath, "out", "", "Output file (defaults to stdout)")

	// enforce required flags
	for _, flag := range []string{"key-type", "key", "in"} {
		if err := cmd.MarkFlagRequired(flag); err != nil {
			panic(err)
		}
	}

	return cmd
}
