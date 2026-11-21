package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// A private key file is either the plain age identity file v1.11.0 used, or
// that same text encrypted with a passphrase in the standard age format
// (scrypt recipient, ASCII armor). The second form is what "age -d -i"
// accepts as an encrypted identity file, so the key stays usable without
// kvage. Which one a file is, is decided by its content, not by its name.

// scryptWorkFactor is the scrypt cost (log2 N) for new key files. Tests
// lower it; 18 is the age default and takes about a second.
var scryptWorkFactor = 18

// readPassphrase asks the user for a passphrase. It is a variable so tests
// can answer without a terminal.
var readPassphrase = ttyPassphrase

// errLocked is returned when the key is passphrase-protected, no session is
// open and the caller asked not to prompt.
var errLocked = errors.New("the key is locked: run `kvage unlock`")

const intro = "age-encryption.org/v1"

func isEncryptedKey(data []byte) bool {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	return bytes.HasPrefix(trimmed, []byte(armor.Header)) || bytes.HasPrefix(trimmed, []byte(intro))
}

// keyFile is a private key file as found on disk.
type keyFile struct {
	path      string
	source    string
	data      []byte
	encrypted bool
}

// id identifies this exact key file content to the session agent.
func (k *keyFile) id() string {
	sum := sha256.Sum256(k.data)
	return hex.EncodeToString(sum[:])
}

func (a *app) loadKeyFile() (*keyFile, error) {
	path, source, err := a.resolveKey()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	return &keyFile{path: path, source: source, data: data, encrypted: isEncryptedKey(data)}, nil
}

// parseIdentityText returns the first X25519 identity of an identity file.
func parseIdentityText(text []byte, path string) (*age.X25519Identity, error) {
	identities, err := age.ParseIdentities(bytes.NewReader(text))
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

// decryptKeyFile opens a passphrase-protected key file.
func decryptKeyFile(data, passphrase []byte, path string) (*age.X25519Identity, error) {
	scrypt, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, err
	}
	var src io.Reader = bytes.NewReader(data)
	if bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte(armor.Header)) {
		src = armor.NewReader(src)
	}
	r, err := age.Decrypt(src, scrypt)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, errors.New("incorrect passphrase")
		}
		return nil, fmt.Errorf("decrypting key file %s: %w", path, err)
	}
	text, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("decrypting key file %s: %w", path, err)
	}
	defer wipe(text)
	return parseIdentityText(text, path)
}

// encryptKeyFile produces the passphrase-protected form of an identity.
func encryptKeyFile(identity *age.X25519Identity, passphrase []byte) ([]byte, error) {
	recipient, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return nil, err
	}
	recipient.SetWorkFactor(scryptWorkFactor)

	var out bytes.Buffer
	armored := armor.NewWriter(&out)
	w, err := age.Encrypt(armored, recipient)
	if err != nil {
		return nil, err
	}
	text := identityFileText(identity)
	if _, err := io.WriteString(w, text); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := armored.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func identityFileText(identity *age.X25519Identity) string {
	return fmt.Sprintf("# created: %s\n# public key: %s\n%s\n",
		time.Now().Format(time.RFC3339), identity.Recipient(), identity)
}

// The public key of a protected key file cannot be read without the
// passphrase, so it is kept next to it in "<key file>.pub". It lets "set"
// encrypt for the own key without unlocking anything.
func pubSidecarPath(keyPath string) string { return keyPath + ".pub" }

func readPubSidecar(keyPath string) (*age.X25519Recipient, error) {
	data, err := os.ReadFile(pubSidecarPath(keyPath))
	if err != nil {
		return nil, err
	}
	return age.ParseX25519Recipient(strings.TrimSpace(string(data)))
}

// wipe overwrites a buffer that held secret material. Go may have made
// other copies it cannot reach, so this is best effort.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// newPassphrase asks for a new passphrase twice.
func newPassphrase(prompt string) ([]byte, error) {
	first, err := readPassphrase(prompt)
	if err != nil {
		return nil, err
	}
	if len(first) == 0 {
		return nil, errors.New("empty passphrase")
	}
	second, err := readPassphrase("Repeat it: ")
	if err != nil {
		return nil, err
	}
	defer wipe(second)
	if !bytes.Equal(first, second) {
		wipe(first)
		return nil, errors.New("the passphrases do not match")
	}
	return first, nil
}
