package sops

import "os"

// Save
// Note: CodeRabbit concerns
//
// os.WriteFile will preserve the existing permissions of a file
// if it already exists (like 0644), meaning there is a brief window
// where the plaintext is written to disk and readable by others before
// your os.Chmod command locks it down.
//
// To fix this race condition, you can use os.OpenFile to get a file handle,
// use f.Chmod(0o600) to restrict the permissions on the empty file descriptor,
// and then write the sensitive data.
//
//	func Save(outFile, data string) error {
//		if err := os.WriteFile(outFile, []byte(data), 0o600); err != nil {
//			return err
//		}
//
//		return os.Chmod(outFile, 0o600)
//	}

// Save
// personal note
// When a file already exists, os.OpenFile with os.O_TRUNC immediately empties it.
// We then lock down the file's permissions to 0600 while it is still empty.
// Only after the file is restricted do we write the decrypted data into it,
// completely eliminating the exposure window.
func Save(outFile, data string) error {
	file, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // G304: File path is intended to be dynamically passed via CLI input variable
	if err != nil {
		return err
	}

	defer func() { _ = file.Close() }()
	if err := file.Chmod(0o600); err != nil {
		return err
	}

	if _, err := file.Write([]byte(data)); err != nil {
		return err
	}

	return file.Close()
}
