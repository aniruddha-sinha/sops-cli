package sops

import (
	"fmt"
	"os"
	"strings"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/cmd/sops/common"
	"github.com/getsops/sops/v3/gcpkms"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/kms"
	"github.com/getsops/sops/v3/pgp"
	sopsstorejson "github.com/getsops/sops/v3/stores/json"
	sopsstoreyaml "github.com/getsops/sops/v3/stores/yaml"
)

type EncryptionAPI interface {
	Encrypt() (string, error)
	Save(data string) error
}
type EncryptSpec struct {
	inputFilePath   string
	outputFilePath  string
	inputFileFormat string
	keyType         string
	keyDetail       string
}

func NewEncryptSpec(inFilePath, outFilePath, inFileFormat, keyType, KeyDetail string) *EncryptSpec {
	return &EncryptSpec{
		inputFilePath:   inFilePath,
		outputFilePath:  outFilePath,
		inputFileFormat: inFileFormat,
		keyType:         keyType,
		keyDetail:       KeyDetail,
	}
}

func (es *EncryptSpec) Encrypt() (string, error) {
	payload, err := os.ReadFile(es.inputFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read the input file %w", err)
	}

	store, err := sopsStoreSelector(es.inputFileFormat)
	if err != nil {
		return "", err
	}

	branches, err := store.LoadPlainFile(payload)
	if err != nil {
		return "", fmt.Errorf("failed to parse %s format", es.inputFileFormat)
	}

	masterKey, err := getProviderWideMasterKey(es.keyType, es.keyDetail)
	if err != nil {
		return "", err
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups: []sops.KeyGroup{
				[]keys.MasterKey{masterKey},
			},
			UnencryptedSuffix: "_unencrypted",
		},
	}

	dataKey, errs := tree.GenerateDataKeyWithKeyServices(
		[]keyservice.KeyServiceClient{keyservice.NewLocalClient()},
	)
	if len(errs) > 0 {
		return "", fmt.Errorf("failed to generate data key. Check your credentials: %v", errs)
	}

	err = common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  aes.NewCipher(),
	})
	if err != nil {
		return "", fmt.Errorf("failed to encrypt tree: %w", err)
	}

	result, err := store.EmitEncryptedFile(tree)
	if err != nil {
		return "", fmt.Errorf("failed to format encrypted output: %w", err)
	}

	return string(result), nil
}

func (es *EncryptSpec) Save(data string) error {
	if err := os.WriteFile(es.outputFilePath, []byte(data), 0o600); err != nil {
		return err
	}

	return nil
}

func sopsStoreSelector(format string) (sops.Store, error) {
	var store sops.Store
	switch strings.ToLower(format) {
	case "json":
		store = &sopsstorejson.Store{}
	case "yaml":
		store = &sopsstoreyaml.Store{}
	case "binary":
		store = &sopsstorejson.BinaryStore{}
	default:
		return nil, fmt.Errorf("unsupported format %s must be json, yaml or binary ", format)
	}

	return store, nil
}

func getProviderWideMasterKey(keyType, keyDetail string) (keys.MasterKey, error) {
	var masterKey keys.MasterKey
	switch strings.ToLower(keyType) {
	case "pgp":
		masterKey = pgp.NewMasterKeyFromFingerprint(keyDetail)
	case "awskms":
		masterKey = kms.NewMasterKey(keyDetail, "", nil)
	case "gcpkms":
		masterKey = gcpkms.NewMasterKeyFromResourceID(keyDetail)
	default:
		return nil, fmt.Errorf("unsupported key type %s", keyType)
	}

	return masterKey, nil
}
