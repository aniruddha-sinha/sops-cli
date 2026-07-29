package sops

import (
	"fmt"
	"os"

	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/keyservice"
)

type DecryptionAPI interface {
	Decrypt() (string, error)
	Save(data string) error
}
type DecryptSpec struct {
	decryptFormat  string
	inputFilePath  string
	outputFilePath string
}

const inputFileFormat = "json"

func NewDecryptSpec(decFormat, inFilePath, outFilePath string) *DecryptSpec {
	return &DecryptSpec{
		decryptFormat:  decFormat,
		inputFilePath:  inFilePath,
		outputFilePath: outFilePath,
	}
}

func (ds *DecryptSpec) Decrypt() (string, error) {
	payload, err := os.ReadFile(ds.inputFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read the input file %w", err)
	}

	inputStore, err := sopsStoreSelector(inputFileFormat)
	if err != nil {
		return "", err
	}

	tree, err := inputStore.LoadEncryptedFile(payload)
	if err != nil {
		return "", fmt.Errorf("failed to parse encrypted JSON file: %w", err)
	}

	keyServiceClient := keyservice.NewLocalClient()
	dataKey, err := tree.Metadata.GetDataKeyWithKeyServices([]keyservice.KeyServiceClient{keyServiceClient}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get data key : %w", err)
	}

	cipher := aes.NewCipher()
	_, err = tree.Decrypt(dataKey, cipher)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt tree: %w", err)
	}

	outputStore, err := sopsStoreSelector(ds.decryptFormat)
	if err != nil {
		return "", err
	}

	result, err := outputStore.EmitPlainFile(tree.Branches)
	if err != nil {
		return "", fmt.Errorf("failed to format decrypted output: %w", err)
	}
	return string(result), nil
}

func (ds *DecryptSpec) Save(data string) error {
	if err := os.WriteFile(ds.outputFilePath, []byte(data), 0o600); err != nil {
		return err
	}

	return nil
}
