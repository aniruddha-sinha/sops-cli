package sops

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/kms"
	"github.com/getsops/sops/v3/pgp"
	sopsstorejson "github.com/getsops/sops/v3/stores/json"
	sopsstoreyaml "github.com/getsops/sops/v3/stores/yaml"
)

var (
	ErrFilePathNotFound = errors.New("file path does not exist")
	ErrKeyTypeInvalid   = errors.New("invalid key type; must be one of pgp, kms")
	ErrFormatInvalid    = errors.New("invalid input file format; defaults to json but can be yaml or binary")
)

func ValidateFilePath(path string) error {
	if path == "" {
		return nil
	}

	if _, err := os.Stat(filepath.Dir(path)); os.IsNotExist(err) {
		return fmt.Errorf("%w: %w", ErrFilePathNotFound, err)
	}

	return nil
}

func ValidateKeyTypeAndGetMasterKey(keyType, keySpec string) ([]keys.MasterKey, error) {
	keySpecSplit := strings.Split(keySpec, ",")
	masterKeys := make([]keys.MasterKey, 0, len(keySpecSplit))
	for _, masterKeySpec := range keySpecSplit {
		key := strings.TrimSpace(masterKeySpec)
		switch strings.ToLower(keyType) {
		case "pgp":
			masterKeys = append(masterKeys, pgp.NewMasterKeyFromFingerprint(key))
		case "kms":
			masterKeys = append(masterKeys, kms.NewMasterKey(key, "", nil))
		default:
			return nil, fmt.Errorf("%w: %s", ErrKeyTypeInvalid, keyType)
		}
	}

	return masterKeys, nil
}

func ValidateFormatAndGetStore(format string) (sops.Store, error) {
	switch strings.ToLower(format) {
	case "json":
		return &sopsstorejson.Store{}, nil
	case "yaml":
		return &sopsstoreyaml.Store{}, nil
	case "binary":
		return &sopsstorejson.BinaryStore{}, nil
	default:
		return nil, fmt.Errorf("%w:%s", ErrFormatInvalid, format)
	}
}
