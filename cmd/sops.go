package cmd

import (
	"fmt"
	"strings"

	"github.com/aniruddha-sinha/sops-cli/internal/sops"
	"github.com/spf13/cobra"
)

func newEncryptCmd() *cobra.Command {
	var inFileFormat, keyType, keyDetail, inputFilePath, outputFilePath string
	cmd := &cobra.Command{
		Use:     "encrypt",
		Aliases: []string{"e"},
		Short:   "encrypt JSON/YAML/BIN secrets with masterkey provider as AWSKMS, PGP",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			inputFileFormat := strings.ToLower(inFileFormat)
			switch inputFileFormat {
			case "json", "yaml", "binary":
			default:
				return fmt.Errorf("invalid input file format %s, must be one of json yaml binary ", inputFileFormat)

			}

			kType := strings.ToLower(keyType)
			switch kType {
			case "awskms", "pgp":
			default:
				return fmt.Errorf("invalid key type %s, must be one of awskms, pgp ", inputFileFormat)
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var encAPI sops.EncryptionAPI = sops.NewEncryptSpec(inputFilePath, outputFilePath, inFileFormat, keyType, keyDetail)
			encryptionOut, err := encAPI.Encrypt()
			if err != nil {
				return err
			}

			if outputFilePath != "" {
				if err := encAPI.Save(encryptionOut); err != nil {
					return err
				}
			} else {
				fmt.Println(encryptionOut)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&inFileFormat, "format", "json", "File Format : JSON/YAML/BIN")
	cmd.Flags().StringVar(&keyType, "key-type", "", "Key Type: awskms, pgp")
	cmd.Flags().StringVar(&keyDetail, "key", "", "key detail: AWS KMS ARN, PGP FINGERPRINT")
	cmd.Flags().StringVar(&inputFilePath, "in", "", "Input file path to encrypt")
	cmd.Flags().StringVar(&outputFilePath, "out", "", "Output file (defaults to stdout)")

	for _, flag := range []string{"key-type", "key", "in"} {
		if err := cmd.MarkFlagRequired(flag); err != nil {
			panic(err)
		}
	}

	return cmd
}
