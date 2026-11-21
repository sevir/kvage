//go:build linux

package main

import (
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// These tests talk to the machine's real TPM and are skipped when the
// current user cannot open it (membership of the tss group is needed).
func needTPM(t *testing.T) {
	t.Helper()
	fd, err := openTPM()
	if err != nil {
		t.Skipf("no usable TPM: %v", err)
	}
	unix.Close(fd)
}

func TestTPMSlotSealsAndUnseals(t *testing.T) {
	needTPM(t)
	var secret [x25519Size]byte
	rand.Read(secret[:])
	want := secret

	slot, err := newTPMSlot(&secret)
	if err != nil {
		t.Fatal(err)
	}
	if secret != want {
		t.Error("newTPMSlot modified the caller's key")
	}
	ts := slot.(*tpmSlot)

	for i := 0; i < 3; i++ {
		var got [x25519Size]byte
		if err := slot.use(func(s *[x25519Size]byte) error { got = *s; return nil }); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatal("unsealed key differs")
		}
		// Between uses the slot holds no trace of the key.
		var zero [x25519Size]byte
		if ts.key != zero {
			t.Error("key left in the slot after use")
		}
		for _, b := range ts.resp {
			if b != 0 {
				t.Fatal("TPM response left in the slot after use")
			}
		}
	}

	// A wrong authorization value is refused by the TPM.
	good := ts.auth
	ts.auth[0] ^= 0xff
	if err := slot.use(func(*[x25519Size]byte) error { return nil }); err == nil {
		t.Error("unsealed with a wrong authorization value")
	}
	// noDA: the failure above must not have locked anything.
	ts.auth = good
	if err := slot.use(func(*[x25519Size]byte) error { return nil }); err != nil {
		t.Errorf("unseal after a failed attempt: %v", err)
	}

	// Another connection to the TPM cannot use the object: handles belong
	// to the file descriptor that created them.
	other, err := openTPM()
	if err != nil {
		t.Fatal(err)
	}
	stolen := &tpmSlot{dev: other, handle: ts.handle, auth: ts.auth}
	if err := stolen.use(func(*[x25519Size]byte) error { return nil }); err == nil {
		t.Error("the sealed object is reachable from another TPM connection")
	}
	unix.Close(other)

	slot.close()
	if err := slot.use(func(*[x25519Size]byte) error { return nil }); err == nil {
		t.Error("slot usable after close")
	}
}

// Several keys can be sealed at once, each on its own connection.
func TestTPMSlotsAreIndependent(t *testing.T) {
	needTPM(t)
	var slots []keySlot
	var keys [][x25519Size]byte
	for i := 0; i < 4; i++ {
		var k [x25519Size]byte
		rand.Read(k[:])
		s, err := newTPMSlot(&k)
		if err != nil {
			t.Fatalf("slot %d: %v", i, err)
		}
		slots, keys = append(slots, s), append(keys, k)
	}
	for i, s := range slots {
		if err := s.use(func(got *[x25519Size]byte) error {
			if *got != keys[i] {
				t.Errorf("slot %d returned another key", i)
			}
			return nil
		}); err != nil {
			t.Errorf("slot %d: %v", i, err)
		}
		s.close()
	}
}

// The whole path: a real agent process, the key sealed in the TPM.
func TestSessionWithTPM(t *testing.T) {
	needTPM(t)
	e := newEnv(t)
	useRealAgent(t)
	writeFile(t, userConfigPath(), "session:\n  tpm: require\n")
	e.mustRun("alpha", "set", "a")
	e.mustRun("beta", "set", "b")
	e.protect("pw")

	p := usePrompts(t, "pw")
	if out, _ := e.mustRun("", "get", "a"); out != "alpha\n" {
		t.Fatalf("get = %q", out)
	}
	if out, _ := e.mustRun("", "list", "--reveal"); out != "a: alpha\nb: beta\n" {
		t.Errorf("list = %q", out)
	}
	if p.asked != 1 {
		t.Errorf("asked %d times, want 1", p.asked)
	}
	out, _ := e.mustRun("", "status")
	if !strings.Contains(out, "sealed in the TPM") {
		t.Errorf("status does not report the TPM:\n%s", out)
	}
	e.mustRun("", "lock")
}
