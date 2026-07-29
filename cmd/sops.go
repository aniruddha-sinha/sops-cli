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
		Short:   "encrypt JSON/YAML/BINARY secrets with masterkey provider as AWSKMS, PGP",
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

	cmd.Flags().StringVar(&inFileFormat, "format", "json", "File Format : JSON/YAML/BINARY")
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

func newDecryptCmd() *cobra.Command {
	var decryptFormat, encryptIn, decryptOut string
	cmd := &cobra.Command{
		Use:     "decrypt",
		Aliases: []string{"d"},
		Short:   "decrypt encrypted JSON secrets into JSON/YAML/BINARY using PGP or AWSKMS Masterkey which can be read from encrypted metadata",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			dFormat := strings.ToLower(decryptFormat)
			switch dFormat {
			case "json", "yaml", "binary":
			default:
				return fmt.Errorf("invalid output file format %s, must be one of json yaml binary ", decryptFormat)
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var decAPI sops.DecryptionAPI = sops.NewDecryptSpec(decryptFormat, encryptIn, decryptOut)
			plainOut, err := decAPI.Decrypt()
			if err != nil {
				return err
			}

			if decryptOut != "" {
				if err := decAPI.Save(plainOut); err != nil {
					return err
				}
			} else {
				fmt.Println(plainOut)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&decryptFormat, "output-format", "", "the format in which the decrypted file needs to be created")
	cmd.Flags().StringVar(&encryptIn, "input-file-path", "", "the input (encrypted) file path")
	cmd.Flags().StringVar(&decryptOut, "output-file-path", "", "the output file path which is plain text; defaults to stdout")
	return cmd
}
