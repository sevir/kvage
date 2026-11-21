//go:build linux || darwin

package main

import (
	"errors"
	"fmt"
)

// keySlot is where the session agent keeps one unlocked key.
type keySlot interface {
	// use calls fn with the key. The buffer is only valid during the call.
	use(fn func(secret *[x25519Size]byte) error) error
	// close erases the key and releases what holds it.
	close()
	describe() string
}

// memSlot keeps the key in the agent's memory for the whole session.
type memSlot struct {
	secret *[x25519Size]byte
	note   string
}

func (s *memSlot) use(fn func(secret *[x25519Size]byte) error) error {
	if s.secret == nil {
		return errors.New("the key is gone")
	}
	return fn(s.secret)
}

func (s *memSlot) close() {
	if s.secret != nil {
		wipe(s.secret[:])
		s.secret = nil
	}
}

func (s *memSlot) describe() string {
	return "in the agent's memory for the whole session" + s.note
}

// newKeySlot stores secret according to session.tpm: "auto" seals it in the
// TPM when there is a usable one and falls back to memory, "off" always
// uses memory, "require" fails without a TPM. secret is left untouched.
func newKeySlot(secret *[x25519Size]byte, tpmMode string) (keySlot, error) {
	note := ""
	if tpmMode != tpmModeOff {
		slot, err := newTPMSlot(secret)
		if err == nil {
			return slot, nil
		}
		if tpmMode == tpmModeRequire {
			return nil, fmt.Errorf("session.tpm is \"require\": %w", err)
		}
		note = fmt.Sprintf(" (TPM not used: %v)", err)
	}
	mem := &memSlot{secret: new([x25519Size]byte), note: note}
	*mem.secret = *secret
	return mem, nil
}
