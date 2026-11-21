package main

import (
	"errors"
	"os"

	"filippo.io/age"
	"golang.org/x/term"
)

// keyring is whatever can decrypt with the own private key: the key itself
// when it is in this process, or the session agent.
type keyring interface {
	// Decrypt returns, for each ciphertext, its plaintext or an error.
	Decrypt(ciphertexts []string) ([]string, []error, error)
	Recipient() (*age.X25519Recipient, error)
}

type localKeyring struct {
	identity *age.X25519Identity
}

func (k *localKeyring) Decrypt(ciphertexts []string) ([]string, []error, error) {
	plain := make([]string, len(ciphertexts))
	errs := make([]error, len(ciphertexts))
	for i, c := range ciphertexts {
		plain[i], errs[i] = decryptValue(c, k.identity)
	}
	return plain, errs, nil
}

func (k *localKeyring) Recipient() (*age.X25519Recipient, error) {
	return k.identity.Recipient(), nil
}

type agentKeyring struct {
	keyID string
}

func (k *agentKeyring) Decrypt(ciphertexts []string) ([]string, []error, error) {
	req := &agentRequest{Op: "decrypt", KeyID: k.keyID, Ciphertexts: make([][]byte, len(ciphertexts))}
	for i, c := range ciphertexts {
		req.Ciphertexts[i] = []byte(c)
	}
	resp, err := agentCall(req)
	if err != nil {
		return nil, nil, err
	}
	if resp.Locked || len(resp.Plaintexts) != len(ciphertexts) || len(resp.Errors) != len(ciphertexts) {
		return nil, nil, errLocked
	}
	plain := make([]string, len(ciphertexts))
	errs := make([]error, len(ciphertexts))
	for i := range ciphertexts {
		if resp.Errors[i] != "" {
			errs[i] = errors.New(resp.Errors[i])
			continue
		}
		plain[i] = string(resp.Plaintexts[i])
		wipe(resp.Plaintexts[i])
	}
	return plain, errs, nil
}

func (k *agentKeyring) Recipient() (*age.X25519Recipient, error) {
	return agentRecipient(k.keyID)
}

// agentRecipient asks the agent for the public key of an unlocked key file.
func agentRecipient(keyID string) (*age.X25519Recipient, error) {
	resp, err := agentCall(&agentRequest{Op: "recipient", KeyID: keyID})
	if err != nil {
		return nil, err
	}
	if resp.Locked || resp.Recipient == "" {
		return nil, errLocked
	}
	return age.ParseX25519Recipient(resp.Recipient)
}

func isTerminal(w any) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// userConfig loads the configuration once per invocation.
func (a *app) userConfig() (*userConfig, error) {
	if a.cfg == nil {
		cfg, err := loadUserConfig()
		if err != nil {
			return nil, err
		}
		a.cfg = cfg
	}
	return a.cfg, nil
}

// keyring returns the means to decrypt with the own key.
//
// A plain key file is used directly. A passphrase-protected one is used
// through the session agent when it already holds the key; otherwise the
// passphrase is asked for on the terminal and, unless session.mode is
// "always", the key is handed to the agent (started if needed) so later
// commands do not ask again. With noPrompt nothing is ever asked: a locked
// key is reported as errLocked.
func (a *app) keyring(noPrompt bool) (keyring, error) {
	if a.kr != nil {
		return a.kr, nil
	}
	kf, err := a.loadKeyFile()
	if err != nil {
		return nil, err
	}
	cfg, err := a.userConfig()
	if err != nil {
		return nil, err
	}

	if !kf.encrypted {
		identity, err := parseIdentityText(kf.data, kf.path)
		if err != nil {
			return nil, err
		}
		warn := cfg.Key.WarnPlaintext == nil || *cfg.Key.WarnPlaintext
		if warn && !noPrompt && isTerminal(a.errw) {
			a.warnf("the private key %s is not passphrase-protected; run `kvage vault init` to protect it", kf.path)
		}
		a.kr = &localKeyring{identity}
		return a.kr, nil
	}

	useAgent := agentSupported && cfg.sessionMode() == sessionModeSession
	if useAgent {
		if _, err := agentRecipient(kf.id()); err == nil {
			a.kr = &agentKeyring{kf.id()}
			return a.kr, nil
		}
	}
	if noPrompt {
		return nil, errLocked
	}

	identity, err := a.askAndDecrypt(kf)
	if err != nil {
		return nil, err
	}
	if useAgent {
		if err := a.addToAgent(kf, identity, cfg); err == nil {
			a.kr = &agentKeyring{kf.id()}
			return a.kr, nil
		} else {
			a.warnf("could not open a session (%v); the passphrase will be asked for again", err)
		}
	}
	a.kr = &localKeyring{identity}
	return a.kr, nil
}

func (a *app) askAndDecrypt(kf *keyFile) (*age.X25519Identity, error) {
	pass, err := readPassphrase("Passphrase for " + kf.path + ": ")
	if err != nil {
		return nil, err
	}
	defer wipe(pass)
	return decryptKeyFile(kf.data, pass, kf.path)
}

func (a *app) addToAgent(kf *keyFile, identity *age.X25519Identity, cfg *userConfig) error {
	timeout, err := cfg.sessionTimeout()
	if err != nil {
		return err
	}
	if err := ensureAgent(timeout, cfg.tpmMode()); err != nil {
		return err
	}
	var secret [x25519Size]byte
	defer wipe(secret[:])
	if err := secretKeyBytes(identity, &secret); err != nil {
		return err
	}
	return agentAdd(kf.id(), kf.path, &secret)
}

// decryptOne decrypts a single ciphertext with the own key.
func (a *app) decryptOne(ciphertext string, noPrompt bool) (string, error) {
	kr, err := a.keyring(noPrompt)
	if err != nil {
		return "", err
	}
	plain, errs, err := kr.Decrypt([]string{ciphertext})
	if err != nil {
		return "", err
	}
	return plain[0], errs[0]
}

// ownRecipient returns the own public key, asking for the passphrase only
// as a last resort: a plain key file, the session agent and the ".pub" file
// written next to a protected key are tried first.
func (a *app) ownRecipient() (*age.X25519Recipient, error) {
	if r, err := a.ownRecipientQuiet(); err != nil || r != nil {
		return r, err
	}
	kr, err := a.keyring(false)
	if err != nil {
		return nil, err
	}
	return kr.Recipient()
}

// ownRecipientQuiet never asks the user for anything. It returns nil
// without error when the public key cannot be known that way.
func (a *app) ownRecipientQuiet() (*age.X25519Recipient, error) {
	if a.kr != nil {
		return a.kr.Recipient()
	}
	kf, err := a.loadKeyFile()
	if err != nil {
		return nil, err
	}
	if !kf.encrypted {
		identity, err := parseIdentityText(kf.data, kf.path)
		if err != nil {
			return nil, err
		}
		return identity.Recipient(), nil
	}
	if agentSupported {
		if r, err := agentRecipient(kf.id()); err == nil {
			return r, nil
		}
	}
	if r, err := readPubSidecar(kf.path); err == nil {
		return r, nil
	}
	return nil, nil
}
