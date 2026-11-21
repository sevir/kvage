package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
)

// keyPath resolves the private key file: --key wins over AGE_KEY_FILE.
func (a *app) keyPath() (string, error) {
	if a.keyFile != "" {
		return a.keyFile, nil
	}
	if p := os.Getenv("AGE_KEY_FILE"); p != "" {
		return p, nil
	}
	return "", errors.New("no key file specified: use the --key flag or set the AGE_KEY_FILE environment variable")
}

// loadIdentity reads an age identity file (comments and blank lines allowed)
// and returns its first X25519 identity.
func loadIdentity(path string) (*age.X25519Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	defer f.Close()

	identities, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("parsing key file %s: %w", path, err)
	}
	for _, id := range identities {
		if x, ok := id.(*age.X25519Identity); ok {
			return x, nil
		}
	}
	return nil, fmt.Errorf("key file %s has no X25519 identity", path)
}

// identity returns the private key selected by flags and environment.
func (a *app) identity() (*age.X25519Identity, error) {
	path, err := a.keyPath()
	if err != nil {
		return nil, err
	}
	return loadIdentity(path)
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

	content := fmt.Sprintf("# created: %s\n# public key: %s\n%s\n",
		time.Now().Format(time.RFC3339),
		identity.Recipient().String(),
		identity.String())

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
