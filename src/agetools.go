package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// loadIdentity reads a plain age identity file (comments and blank lines
// allowed) and returns its first X25519 identity.
func loadIdentity(path string) (*age.X25519Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	return parseIdentityText(data, path)
}

func encryptValue(value string, recipients ...age.Recipient) (string, error) {
	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, recipients...)
	if err != nil {
		return "", err
	}
	if _, err := io.WriteString(w, value); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func decryptValue(encryptedValue string, identities ...age.Identity) (string, error) {
	r, err := age.Decrypt(strings.NewReader(encryptedValue), identities...)
	if err != nil {
		return "", err
	}
	decrypted, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// generateKeyPair writes a new identity to keys/key.txt in the current
// directory. It refuses to overwrite an existing key.
func generateKeyPair(out io.Writer) error {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generating key pair: %w", err)
	}

	keysDir := "keys"
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		return fmt.Errorf("creating keys directory: %w", err)
	}

	content := identityFileText(identity)

	privKeyPath := filepath.Join(keysDir, "key.txt")
	f, err := os.OpenFile(privKeyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists: refusing to overwrite a private key", privKeyPath)
		}
		return fmt.Errorf("saving private key: %w", err)
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return fmt.Errorf("saving private key: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("saving private key: %w", err)
	}

	fmt.Fprintf(out, "Key pairs saved to: %s\n", privKeyPath)
	return nil
}
