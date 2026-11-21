//go:build linux

package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// TPM-guarded session keys.
//
// While a session is open the agent does not keep the private key. It asks
// the TPM to hold it as a sealed object in the NULL hierarchy, protected by
// a random authorization value, and keeps only that value and the object
// handle. For each request the key is unsealed into a buffer, used, and
// erased again.
//
// What this buys: a memory image of the machine (hibernation file, swap,
// crash dump, cold boot) holds the authorization value but not the key, and
// the value is useless without this TPM in this very boot, because the seed
// of the NULL hierarchy is regenerated on every TPM reset. It buys nothing
// against root or against the agent's own user while the session is open:
// whoever can read the agent's memory can ask the TPM to unseal too.
//
// The three TPM commands needed are encoded by hand rather than through a
// TPM library, so that every buffer the key passes through belongs to this
// file and can be erased. Authorization is a plain password session: the
// key and the authorization value are not encrypted on the way to the TPM.
// A probe on the TPM bus of a running, unlocked machine is outside what
// this feature defends against.
//
// The object is created with noDA, so failed authorizations never count
// towards the TPM's dictionary attack lockout, and a lockout caused by
// something else does not affect it.

const tpmDevicePath = "/dev/tpmrm0"

const (
	tpmSTNoSessions = 0x8001
	tpmSTSessions   = 0x8002

	tpmCCCreatePrimary = 0x00000131
	tpmCCUnseal        = 0x0000015E
	tpmCCFlushContext  = 0x00000165

	tpmRHNull = 0x40000007
	tpmRSPW   = 0x40000009

	tpmAlgKeyedHash = 0x0008
	tpmAlgSHA256    = 0x000B
	tpmAlgNull      = 0x0010

	// fixedTPM | fixedParent | userWithAuth | noDA. sensitiveDataOrigin is
	// clear: the sealed data is supplied by the caller.
	tpmSealedAttributes = 0x00000002 | 0x00000010 | 0x00000040 | 0x00000400

	tpmHeaderSize = 10
	tpmAuthSize   = 32
)

var errTPMUnavailable = errors.New("no usable TPM")

// tpmSlot holds one key sealed in the TPM. The device stays open for the
// life of the slot: the kernel resource manager ties the object to this
// file descriptor and flushes it when the descriptor is closed.
type tpmSlot struct {
	dev    int // file descriptor, -1 once closed
	handle uint32
	auth   [tpmAuthSize]byte
	key    [x25519Size]byte // only filled during use
	resp   [128]byte        // response buffer of Unseal, erased after use
}

// openTPM opens the TPM through the kernel resource manager. The descriptor
// is a plain blocking one on purpose: on a non-blocking descriptor the
// kernel runs the command in the background and a read can come back empty.
func openTPM() (int, error) {
	return unix.Open(tpmDevicePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
}

// tpmCommand sends one command and reads its response into resp. It returns
// the response length after checking the header and the response code.
func tpmCommand(dev int, cmd, resp []byte) (int, error) {
	if _, err := unix.Write(dev, cmd); err != nil {
		return 0, fmt.Errorf("writing to the TPM: %w", err)
	}
	n, err := unix.Read(dev, resp)
	if err != nil {
		return 0, fmt.Errorf("reading from the TPM: %w", err)
	}
	if n < tpmHeaderSize || int(binary.BigEndian.Uint32(resp[2:6])) != n {
		return 0, errors.New("malformed TPM response")
	}
	if rc := binary.BigEndian.Uint32(resp[6:10]); rc != 0 {
		return 0, fmt.Errorf("TPM error 0x%08x", rc)
	}
	return n, nil
}

// passwordAuth appends a password authorization area (with its size field).
func passwordAuth(b []byte, auth []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(4+2+1+2+len(auth)))
	b = binary.BigEndian.AppendUint32(b, tpmRSPW)
	b = binary.BigEndian.AppendUint16(b, 0) // nonce
	b = append(b, 0)                        // session attributes
	b = binary.BigEndian.AppendUint16(b, uint16(len(auth)))
	return append(b, auth...)
}

func tpmHeader(tag uint16, code uint32) []byte {
	b := make([]byte, 0, 256)
	b = binary.BigEndian.AppendUint16(b, tag)
	b = binary.BigEndian.AppendUint32(b, 0) // size, set by tpmFinish
	return binary.BigEndian.AppendUint32(b, code)
}

func tpmFinish(b []byte) []byte {
	binary.BigEndian.PutUint32(b[2:6], uint32(len(b)))
	return b
}

// newTPMSlot seals secret in the TPM. It does not keep or modify secret.
func newTPMSlot(secret *[x25519Size]byte) (keySlot, error) {
	dev, err := openTPM()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errTPMUnavailable, err)
	}
	s := &tpmSlot{dev: dev}
	if _, err := rand.Read(s.auth[:]); err != nil {
		unix.Close(dev)
		return nil, err
	}
	// The TPM drops trailing zero bytes of an authorization value; keep
	// the last byte non-zero so the value is used at full length.
	s.auth[tpmAuthSize-1] |= 1

	// TPM2_CreatePrimary(TPM_RH_NULL) of a sealed data object.
	cmd := tpmHeader(tpmSTSessions, tpmCCCreatePrimary)
	cmd = binary.BigEndian.AppendUint32(cmd, tpmRHNull)
	cmd = passwordAuth(cmd, nil) // the NULL hierarchy has an empty auth
	// inSensitive: TPM2B_SENSITIVE_CREATE { userAuth, data }
	cmd = binary.BigEndian.AppendUint16(cmd, uint16(2+tpmAuthSize+2+x25519Size))
	cmd = binary.BigEndian.AppendUint16(cmd, tpmAuthSize)
	cmd = append(cmd, s.auth[:]...)
	cmd = binary.BigEndian.AppendUint16(cmd, x25519Size)
	cmd = append(cmd, secret[:]...)
	// inPublic: TPM2B_PUBLIC { type, nameAlg, attributes, authPolicy,
	// keyedHash scheme, unique }
	cmd = binary.BigEndian.AppendUint16(cmd, 2+2+4+2+2+2)
	cmd = binary.BigEndian.AppendUint16(cmd, tpmAlgKeyedHash)
	cmd = binary.BigEndian.AppendUint16(cmd, tpmAlgSHA256)
	cmd = binary.BigEndian.AppendUint32(cmd, tpmSealedAttributes)
	cmd = binary.BigEndian.AppendUint16(cmd, 0)
	cmd = binary.BigEndian.AppendUint16(cmd, tpmAlgNull)
	cmd = binary.BigEndian.AppendUint16(cmd, 0)
	cmd = binary.BigEndian.AppendUint16(cmd, 0) // outsideInfo
	cmd = binary.BigEndian.AppendUint32(cmd, 0) // creationPCR
	cmd = tpmFinish(cmd)
	defer wipe(cmd[:cap(cmd)])

	resp := make([]byte, 1024)
	n, err := tpmCommand(dev, cmd, resp)
	if err != nil {
		unix.Close(dev)
		return nil, fmt.Errorf("%w: sealing the key: %v", errTPMUnavailable, err)
	}
	if n < tpmHeaderSize+4 {
		unix.Close(dev)
		return nil, fmt.Errorf("%w: short CreatePrimary response", errTPMUnavailable)
	}
	s.handle = binary.BigEndian.Uint32(resp[tpmHeaderSize:])

	// Prove the object works before the caller erases its copy of the key.
	if err := s.use(func(got *[x25519Size]byte) error {
		if *got != *secret {
			return errors.New("the TPM returned different data")
		}
		return nil
	}); err != nil {
		s.close()
		return nil, fmt.Errorf("%w: %v", errTPMUnavailable, err)
	}
	return s, nil
}

// use unseals the key for the duration of fn.
func (s *tpmSlot) use(fn func(secret *[x25519Size]byte) error) error {
	if s.dev < 0 {
		return errors.New("the TPM session object is gone")
	}
	cmd := tpmHeader(tpmSTSessions, tpmCCUnseal)
	cmd = binary.BigEndian.AppendUint32(cmd, s.handle)
	cmd = tpmFinish(passwordAuth(cmd, s.auth[:]))
	defer wipe(cmd[:cap(cmd)])
	defer wipe(s.resp[:])
	defer wipe(s.key[:])

	n, err := tpmCommand(s.dev, cmd, s.resp[:])
	if err != nil {
		return fmt.Errorf("unsealing the key: %w", err)
	}
	// header, parameterSize(4), TPM2B outData
	const dataAt = tpmHeaderSize + 4 + 2
	if n < dataAt+x25519Size || binary.BigEndian.Uint16(s.resp[tpmHeaderSize+4:]) != x25519Size {
		return errors.New("unexpected Unseal response")
	}
	copy(s.key[:], s.resp[dataAt:dataAt+x25519Size])
	return fn(&s.key)
}

func (s *tpmSlot) close() {
	if s.dev < 0 {
		return
	}
	cmd := tpmHeader(tpmSTNoSessions, tpmCCFlushContext)
	cmd = tpmFinish(binary.BigEndian.AppendUint32(cmd, s.handle))
	resp := make([]byte, 64)
	tpmCommand(s.dev, cmd, resp)
	unix.Close(s.dev)
	s.dev = -1
	wipe(s.auth[:])
}

func (s *tpmSlot) describe() string {
	return "sealed in the TPM, in memory only while decrypting"
}
