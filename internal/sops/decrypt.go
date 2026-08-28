package sops

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/decrypt"
)

var (
	ErrFormattingPlainOut   = errors.New("failed to format plaintext out")
	ErrDecryptFailed        = errors.New("failed to decrypt sops encrypted data")
	ErrParsingDecryptedData = errors.New("error parsing decrypted data for format conversion")
)

func Decrypt(inFormat, outFormat, inFile string) (string, error) {
	inFormat = strings.ToLower(inFormat)
	outFormat = strings.ToLower(outFormat)
	payload, err := os.ReadFile(inFile) //nolint:gosec // G304: File path is intended to be dynamically passed via CLI input variable
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInFileReadError, err)
	}

	inFmt := formats.FormatFromString(inFormat)
	plaintext, err := decrypt.DataWithFormat(payload, inFmt)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrDecryptFailed, err)
	}

	if inFormat == outFormat {
		return string(plaintext), nil
	}

	result, err := formatDecryptedData(inFormat, outFormat, &plaintext)
	if err != nil {
		return "", err
	}

	return string(*result), nil
}

func formatDecryptedData(inFormat, outFormat string, plaintext *[]byte) (*[]byte, error) {
	inStore, err := ValidateFormatAndGetStore(inFormat)
	if err != nil {
		return nil, err
	}

	branches, err := inStore.LoadPlainFile(*plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParsingDecryptedData, err)
	}

	outStore, err := ValidateFormatAndGetStore(outFormat)
	if err != nil {
		return nil, err
	}

	result, err := outStore.EmitPlainFile(branches)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFormattingPlainOut, err)
	}

	return &result, nil
}
