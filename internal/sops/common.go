package sops

import "os"

func Save(outFile, data string) error {
	if err := os.WriteFile(outFile, []byte(data), 0o600); err != nil {
		return err
	}

	return os.Chmod(outFile, 0o600)
}
