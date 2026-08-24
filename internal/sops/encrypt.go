package sops

import (
	"errors"
	"fmt"
	"os"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/keyservice"
)

var (
	ErrInFileReadError           = errors.New("failed to read input file")
	ErrGenDataKey                = errors.New("failed to generate data key; check your credentials")
	ErrEncryptingTree            = errors.New("failed to encrypt tree")
	ErrFormattingEncryptedOutput = errors.New("failed to format encrypted output")
)

func Encrypt(inFile, format, keyType, keySpec string) (string, error) {
	payload, err := os.ReadFile(inFile)
	if err != nil {
		return "", fmt.Errorf("%w, %w", ErrInFileReadError, err)
	}

	store, branches, err := loadPlainFile(payload, format)
	if err != nil {
		return "", err
	}

	masterKeys, err := ValidateKeyTypeAndGetMasterKey(keyType, keySpec)
	if err != nil {
		return "", err
	}

	tree := getSopsEncryptionTree(branches, masterKeys)
	dataKey, err := generateDataKey(&tree)
	if err != nil {
		return "", fmt.Errorf("%w:%w", ErrGenDataKey, err)
	}

	result, err := encryptAndEmit(store, dataKey, tree)
	if err != nil {
		return "", err
	}

	return string(result), err
}

func Save(outFile, data string) error {
	if err := os.WriteFile(outFile, []byte(data), 0o600); err != nil {
		return err
	}

	return os.Chmod(outFile, 0o600)
}

func encryptAndEmit(store sops.Store, dataKey []byte, tree sops.Tree) ([]byte, error) {
	if err := common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  aes.NewCipher(),
	}); err != nil {
		return nil, fmt.Errorf("%w:%w", ErrEncryptingTree, err)
	}

	result, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFormattingEncryptedOutput, err)
	}

	return result, nil
}

func generateDataKey(tree *sops.Tree) ([]byte, error) {
	dataKey, errs := tree.GenerateDataKeyWithKeyServices([]keyservice.KeyServiceClient{
		keyservice.NewLocalClient(),
	})

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return dataKey, nil
}

func loadPlainFile(payload []byte, format string) (sops.Store, sops.TreeBranches, error) {
	sopsStore, err := ValidateFormatAndGetStore(format)
	if err != nil {
		return nil, nil, err
	}

	branches, err := sopsStore.LoadPlainFile(payload)
	if err != nil {
		return nil, nil, err
	}

	return sopsStore, branches, nil
}

func getSopsEncryptionTree(branches sops.TreeBranches, masterKeys []keys.MasterKey) sops.Tree {
	return sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{
				masterKeys,
			},

			UnencryptedSuffix: "_unencrypted",
		},
	}
}
