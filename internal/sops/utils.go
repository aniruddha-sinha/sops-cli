package sops

import (
	"fmt"
	"strings"

	"github.com/getsops/sops/v3"
	sopsstorejson "github.com/getsops/sops/v3/stores/json"
	sopsstoreyaml "github.com/getsops/sops/v3/stores/yaml"
)

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
