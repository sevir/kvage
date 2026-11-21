package main

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"filippo.io/age"
	"filippo.io/edwards25519/field"
	"golang.org/x/crypto/chacha20poly1305"
)

// The session agent must be able to erase the private key from its memory
// after every use. age.X25519Identity cannot do that: it keeps the key in
// unexported fields and computes with crypto/ecdh, which makes copies that
// nobody can reach. This file is an age.Identity whose key lives in one
// caller-owned buffer and whose scalar multiplication keeps its working
// state in variables that are zeroed before returning.
//
// Only the X25519 recipient stanza is handled here. Everything else about
// decrypting an age file (header MAC, payload) is still done by
// filippo.io/age, which calls Unwrap.
//
// Erasure is best effort: the Go runtime may still copy stack frames. The
// file key and the wrapping key of each message are not long-term secrets
// and are left to the garbage collector.

const (
	x25519Size      = 32
	x25519Label     = "age-encryption.org/v1/X25519"
	ageFileKeySize  = 16
	secretKeyHRP    = "age-secret-key-"
	recipientKeyHRP = "age"
)

var x25519Basepoint = [x25519Size]byte{9}

// x25519 computes the X25519 function of RFC 7748 into dst. scalar is read
// but never copied anywhere that outlives the call.
func x25519(dst, scalar, point *[x25519Size]byte) {
	var k [x25519Size]byte
	copy(k[:], scalar[:])
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64

	var x1, x2, z2, x3, z3, a, aa, b, bb, e, c, d, da, cb, t field.Element
	x1.SetBytes(point[:]) // the top bit is ignored, as RFC 7748 requires
	x2.One()
	z2.Zero()
	x3.Set(&x1)
	z3.One()

	swap := 0
	for pos := 254; pos >= 0; pos-- {
		bit := int(k[pos/8]>>(pos%8)) & 1
		swap ^= bit
		x2.Swap(&x3, swap)
		z2.Swap(&z3, swap)
		swap = bit

		a.Add(&x2, &z2)
		aa.Square(&a)
		b.Subtract(&x2, &z2)
		bb.Square(&b)
		e.Subtract(&aa, &bb)
		c.Add(&x3, &z3)
		d.Subtract(&x3, &z3)
		da.Multiply(&d, &a)
		cb.Multiply(&c, &b)

		t.Add(&da, &cb)
		x3.Square(&t)
		t.Subtract(&da, &cb)
		t.Square(&t)
		z3.Multiply(&x1, &t)
		x2.Multiply(&aa, &bb)
		t.Mult32(&e, 121665)
		t.Add(&aa, &t)
		z2.Multiply(&e, &t)
	}
	x2.Swap(&x3, swap)
	z2.Swap(&z3, swap)

	z2.Invert(&z2)
	x2.Multiply(&x2, &z2)
	copy(dst[:], x2.Bytes())

	// Erase everything derived from the scalar.
	var zero field.Element
	for _, v := range []*field.Element{&x2, &z2, &x3, &z3, &a, &aa, &b, &bb, &e, &c, &d, &da, &cb, &t} {
		v.Set(&zero)
	}
	wipe(k[:])
}

// secretIdentity is an age.Identity over a key buffer owned by the caller.
// It is only valid while that buffer holds the key.
type secretIdentity struct {
	secret *[x25519Size]byte
	public [x25519Size]byte
}

// publicFromSecret derives the X25519 public key.
func publicFromSecret(secret *[x25519Size]byte) (pub [x25519Size]byte) {
	x25519(&pub, secret, &x25519Basepoint)
	return pub
}

func newSecretIdentity(secret *[x25519Size]byte, public [x25519Size]byte) *secretIdentity {
	return &secretIdentity{secret: secret, public: public}
}

var _ age.Identity = (*secretIdentity)(nil)

// Unwrap returns the file key of the first stanza addressed to this key.
// It mirrors (*age.X25519Identity).Unwrap.
func (i *secretIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	for _, s := range stanzas {
		fileKey, err := i.unwrap(s)
		if errors.Is(err, age.ErrIncorrectIdentity) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return fileKey, nil
	}
	return nil, age.ErrIncorrectIdentity
}

func (i *secretIdentity) unwrap(s *age.Stanza) ([]byte, error) {
	if s.Type != "X25519" {
		return nil, age.ErrIncorrectIdentity
	}
	if len(s.Args) != 1 {
		return nil, errors.New("invalid X25519 recipient block")
	}
	share, err := base64.RawStdEncoding.Strict().DecodeString(s.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse X25519 recipient: %v", err)
	}
	if len(share) != x25519Size {
		return nil, errors.New("invalid X25519 recipient block")
	}

	var shared, peer [x25519Size]byte
	copy(peer[:], share)
	x25519(&shared, i.secret, &peer)
	defer wipe(shared[:])
	// An all-zero result means a low-order point: reject it, as
	// crypto/ecdh and x/crypto do.
	var zero [x25519Size]byte
	if subtle.ConstantTimeCompare(shared[:], zero[:]) == 1 {
		return nil, errors.New("invalid X25519 recipient: bad input point")
	}

	salt := make([]byte, 0, 2*x25519Size)
	salt = append(salt, share...)
	salt = append(salt, i.public[:]...)
	wrappingKey, err := hkdf.Key(sha256.New, shared[:], salt, x25519Label, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	defer wipe(wrappingKey)

	aead, err := chacha20poly1305.New(wrappingKey)
	if err != nil {
		return nil, err
	}
	if len(s.Body) != ageFileKeySize+aead.Overhead() {
		return nil, errors.New("invalid X25519 recipient block: incorrect file key size")
	}
	fileKey, err := aead.Open(nil, make([]byte, chacha20poly1305.NonceSize), s.Body, nil)
	if err != nil {
		return nil, age.ErrIncorrectIdentity
	}
	return fileKey, nil
}

// ---- Bech32 (BIP 173), as used by age for keys ----

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func bech32Polymod(values []byte) uint32 {
	gen := [...]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := uint32(1)
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, 2*len(hrp)+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

// convertBits regroups bits; pad is true when encoding (8 to 5).
func convertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	var acc uint32
	var bits uint
	out := make([]byte, 0, len(data)*int(from)/int(to)+1)
	maxv := uint32(1)<<to - 1
	for _, b := range data {
		if uint32(b)>>from != 0 {
			return nil, errors.New("invalid bech32 data")
		}
		acc = acc<<from | uint32(b)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte(acc<<(to-bits)&maxv))
		}
	} else if bits >= from || acc<<(to-bits)&maxv != 0 {
		return nil, errors.New("invalid bech32 padding")
	}
	return out, nil
}

func bech32Encode(hrp string, data []byte) string {
	values, _ := convertBits(data, 8, 5, true)
	check := append(bech32HRPExpand(hrp), values...)
	check = append(check, 0, 0, 0, 0, 0, 0)
	mod := bech32Polymod(check) ^ 1
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, v := range values {
		sb.WriteByte(bech32Charset[v])
	}
	for i := 0; i < 6; i++ {
		sb.WriteByte(bech32Charset[mod>>(5*(5-i))&31])
	}
	return sb.String()
}

// bech32Decode decodes s, which must be all lower or all upper case, and
// returns its lower-case prefix and data. The 5-bit working copy of the
// data is erased before returning.
func bech32Decode(s string) (string, []byte, error) {
	lower, upper := strings.ToLower(s), strings.ToUpper(s)
	if s != lower && s != upper {
		return "", nil, errors.New("mixed case bech32 string")
	}
	pos := strings.LastIndexByte(lower, '1')
	if pos < 1 || pos+7 > len(lower) {
		return "", nil, errors.New("malformed bech32 string")
	}
	hrp := lower[:pos]
	values := make([]byte, 0, len(lower)-pos-1)
	defer func() { wipe(values[:cap(values)]) }()
	for i := pos + 1; i < len(lower); i++ {
		v := strings.IndexByte(bech32Charset, lower[i])
		if v < 0 {
			return "", nil, errors.New("invalid bech32 character")
		}
		values = append(values, byte(v))
	}
	check := append(bech32HRPExpand(hrp), values...)
	defer wipe(check)
	if bech32Polymod(check) != 1 {
		return "", nil, errors.New("invalid bech32 checksum")
	}
	data, err := convertBits(values[:len(values)-6], 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, data, nil
}

// secretKeyBytes extracts the raw key of an age X25519 identity into dst.
func secretKeyBytes(identity *age.X25519Identity, dst *[x25519Size]byte) error {
	hrp, data, err := bech32Decode(identity.String())
	if err != nil {
		return err
	}
	defer wipe(data)
	if hrp != secretKeyHRP || len(data) != x25519Size {
		return errors.New("not an X25519 identity")
	}
	copy(dst[:], data)
	return nil
}

// recipientString formats a public key the way age prints recipients.
func recipientKeyString(public [x25519Size]byte) string {
	return bech32Encode(recipientKeyHRP, public[:])
}
