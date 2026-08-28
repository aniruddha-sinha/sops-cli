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

	for _, flag := range []string{"key-type", "key", "in"} {
		if err := cmd.MarkFlagRequired(flag); err != nil {
			return nil
		}
	}

	return cmd
}

func newDecryptCmd() *cobra.Command {
	var inFormat, outFormat, inFile, outFile string
	cmd := &cobra.Command{
		Use:     "decrypt",
		Aliases: []string{"d"},
		Short:   "decrypt encrypted JSON secrets into JSON/YAML/BINARY using PGP or KMS master key which can be read from encrypted metadata",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := sops.ValidateFilePath(inFile); err != nil {
				return err
			}

			if err := sops.ValidateFilePath(outFile); err != nil {
				return err
			}

			if _, err := sops.ValidateFormatAndGetStore(inFormat); err != nil {
				return err
			}

			if _, err := sops.ValidateFormatAndGetStore(outFormat); err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			decOut, err := sops.Decrypt(inFormat, outFormat, inFile)
			if err != nil {
				return err
			}

			if outFile == "" {
				fmt.Println(decOut)
				return nil
			}

			return sops.Save(outFile, decOut)
		},
	}

	cmd.Flags().StringVar(&inFormat, "in-format", "json", "the format of the encrypted file ")
	cmd.Flags().StringVar(&outFormat, "out-format", "json", "the desired format of the decrypted/plaintext file")
	cmd.Flags().StringVar(&inFile, "in", "", "the input (encrypted) file path")
	cmd.Flags().StringVar(&outFile, "out", "", "the output file path which is plain text; defaults to stdout")
	return cmd
}
