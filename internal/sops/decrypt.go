package sops

import (
	"errors"
	"fmt"
	"os"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/keyservice"
)

var (
	ErrEncryptedFileRead  = errors.New("failed to parse encrypted file")
	ErrRetrievingDataKey  = errors.New("error getting data key")
	ErrDecryptingTree     = errors.New("error decrypting sops tree")
	ErrFormattingPlainOut = errors.New("failed to format plaintext out")
)

func Decrypt(inFormat, outFormat, inFile string) (string, error) {
	payload, err := os.ReadFile(inFile) //nolint:gosec // G304: File path is intended to be dynamically passed via CLI input variable
	if err != nil {
		return "", fmt.Errorf("%w, %w", ErrInFileReadError, err)
	}

	tree, err := loadEncryptedFile(payload, inFormat)
	if err != nil {
		return "", err
	}

	keyServiceClient := keyservice.NewLocalClient()
	dataKey, err := getDataKey(&keyServiceClient, tree)
	if err != nil {
		return "", err
	}

	result, err := decryptAndEmit(outFormat, dataKey, tree)
	if err != nil {
		return "", err
	}

	return string(result), nil
}

func loadEncryptedFile(payload []byte, format string) (*sops.Tree, error) {
	store, err := ValidateFormatAndGetStore(format)
	if err != nil {
		return nil, err
	}

	tree, err := store.LoadEncryptedFile(payload)
	if err != nil {
		return nil, fmt.Errorf("%w:%w", ErrEncryptedFileRead, err)
	}

	return &tree, nil
}

func getDataKey(ksClient *keyservice.LocalClient, tree *sops.Tree) (*[]byte, error) {
	dataKey, err := tree.Metadata.GetDataKeyWithKeyServices(
		[]keyservice.KeyServiceClient{
			ksClient,
		}, nil)
	if err != nil {
		return nil, fmt.Errorf("%w:%w", ErrRetrievingDataKey, err)
	}

	return &dataKey, nil
}

func decryptAndEmit(outFormat string, dataKey *[]byte, tree *sops.Tree) ([]byte, error) {
	cipher := aes.NewCipher()
	_, err := tree.Decrypt(*dataKey, cipher)
	if err != nil {
		return nil, fmt.Errorf("%w:%w", ErrDecryptingTree, err)
	}

	outStore, err := ValidateFormatAndGetStore(outFormat)
	if err != nil {
		return nil, err
	}

	result, err := outStore.EmitPlainFile(tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("%w:%w", ErrFormattingPlainOut, err)
	}

	return result, nil
}
