package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
)

func getKeyFromFile(keyPath string) (*age.X25519Identity, error) {
	content, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	if len(lines) < 3 {
		return nil, fmt.Errorf("invalid key file format")
	}

	identity, err := age.ParseX25519Identity(lines[2])
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return identity, nil
}

func getPrivateKey(keyFile string) (*age.X25519Identity, error) {
	keyPath := os.Getenv("AGE_KEY_FILE")
	if keyPath == "" {
		keyPath = keyFile
	}
	if keyPath == "" {
		return nil, fmt.Errorf("no key file specified")
	}
	return getKeyFromFile(keyPath)
}

func encryptValue(value string, identity *age.X25519Identity) (string, error) {
	recipient := identity.Recipient()
	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, recipient)
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

func decryptValue(encryptedValue string, identity *age.X25519Identity) (string, error) {
	r, err := age.Decrypt(strings.NewReader(encryptedValue), identity)
	if err != nil {
		return "", err
	}

	decrypted, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func generateKeyPair() error {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("error generating key pair: %v", err)
	}

	keysDir := "keys"
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return fmt.Errorf("error creating keys directory: %v", err)
	}

	creationTime := time.Now().Format(time.RFC3339)
	publicKey := identity.Recipient().String()
	privateKeyContent := fmt.Sprintf("# created: %s\n# public key: %s\n%s",
		creationTime,
		publicKey,
		identity.String())

	privKeyPath := filepath.Join(keysDir, "key.txt")
	if err := os.WriteFile(privKeyPath, []byte(privateKeyContent), 0600); err != nil {
		return fmt.Errorf("error saving private key: %v", err)
	}

	fmt.Printf("Key pairs saved to: %s\n", privKeyPath)
	return nil
}
