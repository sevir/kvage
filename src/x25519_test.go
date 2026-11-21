package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
)

func unhex(t *testing.T, s string) (out [32]byte) {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad hex %q", s)
	}
	copy(out[:], b)
	return out
}

// Test vectors of RFC 7748, section 5.2 and 6.1.
func TestX25519RFC7748(t *testing.T) {
	for _, v := range []struct{ scalar, point, want string }{
		{"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
			"e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
			"c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"},
		{"4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
			"e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
			"95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"},
		{"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
			"0900000000000000000000000000000000000000000000000000000000000000",
			"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"},
		{"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
			"de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
			"4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"},
	} {
		scalar, point, want := unhex(t, v.scalar), unhex(t, v.point), unhex(t, v.want)
		var got [32]byte
		x25519(&got, &scalar, &point)
		if got != want {
			t.Errorf("x25519(%s, %s) = %x, want %s", v.scalar, v.point, got, v.want)
		}
		if scalar != unhex(t, v.scalar) {
			t.Error("x25519 modified its scalar")
		}
	}
}

func TestX25519MatchesStandardLibrary(t *testing.T) {
	curve := ecdh.X25519()
	for i := 0; i < 500; i++ {
		var scalar [32]byte
		rand.Read(scalar[:])
		priv, err := curve.NewPrivateKey(scalar[:])
		if err != nil {
			t.Fatal(err)
		}
		peer, _ := curve.GenerateKey(rand.Reader)
		var peerPub [32]byte
		copy(peerPub[:], peer.PublicKey().Bytes())

		if pub := publicFromSecret(&scalar); !bytes.Equal(pub[:], priv.PublicKey().Bytes()) {
			t.Fatalf("public key mismatch for scalar %x", scalar)
		}
		want, err := priv.ECDH(peer.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		var got [32]byte
		x25519(&got, &scalar, &peerPub)
		if !bytes.Equal(got[:], want) {
			t.Fatalf("shared secret mismatch for scalar %x", scalar)
		}
	}
}

func TestBech32AgainstAge(t *testing.T) {
	for i := 0; i < 200; i++ {
		id := newIdentity(t)
		var secret [32]byte
		if err := secretKeyBytes(id, &secret); err != nil {
			t.Fatal(err)
		}
		if got := strings.ToUpper(bech32Encode(secretKeyHRP, secret[:])); got != id.String() {
			t.Fatalf("identity round trip: %s != %s", got, id)
		}
		if got := recipientKeyString(publicFromSecret(&secret)); got != id.Recipient().String() {
			t.Fatalf("recipient: %s != %s", got, id.Recipient())
		}
	}
	for _, bad := range []string{"", "age1", "AGE-SECRET-KEY-1QQQQ", "Age1qqqqqqqq", "age1qqqqqqqqb", "noseparator"} {
		if _, _, err := bech32Decode(bad); err == nil {
			t.Errorf("bech32Decode(%q) succeeded", bad)
		}
	}
	// A corrupted checksum is rejected.
	s := []byte(newIdentity(t).String())
	if s[len(s)-1] == 'Q' {
		s[len(s)-1] = 'P'
	} else {
		s[len(s)-1] = 'Q'
	}
	if _, _, err := bech32Decode(string(s)); err == nil {
		t.Error("corrupted checksum accepted")
	}
}

func testSecretIdentity(t *testing.T, id *age.X25519Identity) (*secretIdentity, *[32]byte) {
	t.Helper()
	secret := new([32]byte)
	if err := secretKeyBytes(id, secret); err != nil {
		t.Fatal(err)
	}
	return newSecretIdentity(secret, publicFromSecret(secret)), secret
}

// Files encrypted by filippo.io/age are decrypted through secretIdentity,
// alone and among several recipients, exactly as the library's own identity.
func TestSecretIdentityDecryptsAgeFiles(t *testing.T) {
	for i := 0; i < 50; i++ {
		id, other := newIdentity(t), newIdentity(t)
		mine, _ := testSecretIdentity(t, id)
		payload := make([]byte, i*37)
		rand.Read(payload)

		for _, recipients := range [][]age.Recipient{
			{id.Recipient()},
			{other.Recipient(), id.Recipient()},
			{id.Recipient(), other.Recipient(), newIdentity(t).Recipient()},
		} {
			var buf bytes.Buffer
			w, err := age.Encrypt(&buf, recipients...)
			if err != nil {
				t.Fatal(err)
			}
			w.Write(payload)
			w.Close()

			r, err := age.Decrypt(bytes.NewReader(buf.Bytes()), mine)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			got, _ := io.ReadAll(r)
			if !bytes.Equal(got, payload) {
				t.Fatal("payload mismatch")
			}
		}
	}
}

func TestSecretIdentityRejectsWhatIsNotForIt(t *testing.T) {
	id, other := newIdentity(t), newIdentity(t)
	mine, _ := testSecretIdentity(t, id)

	enc, _ := encryptValue("x", other.Recipient())
	if _, err := decryptValue(enc, mine); err == nil {
		t.Error("decrypted a file for another recipient")
	}

	// Tampered stanza body: authentication must fail, not panic.
	enc, _ = encryptValue("x", id.Recipient())
	lines := strings.SplitN(enc, "\n", 4)
	body := []byte(lines[2])
	if body[0] == 'A' {
		body[0] = 'B'
	} else {
		body[0] = 'A'
	}
	lines[2] = string(body)
	if _, err := decryptValue(strings.Join(lines, "\n"), mine); err == nil {
		t.Error("tampered stanza accepted")
	}

	// Malformed stanzas produce errors, as in the library.
	for _, s := range []*age.Stanza{
		{Type: "X25519", Args: nil, Body: make([]byte, 32)},
		{Type: "X25519", Args: []string{"!!!"}, Body: make([]byte, 32)},
		{Type: "X25519", Args: []string{"AAAA"}, Body: make([]byte, 32)},
		{Type: "X25519", Args: []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, Body: make([]byte, 32)}, // zero point
		{Type: "X25519", Args: []string{"CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, Body: make([]byte, 5)},
	} {
		if _, err := mine.Unwrap([]*age.Stanza{s}); err == nil {
			t.Errorf("malformed stanza %+v accepted", s)
		}
	}
	if _, err := mine.Unwrap([]*age.Stanza{{Type: "scrypt"}}); err != age.ErrIncorrectIdentity {
		t.Errorf("foreign stanza type: err = %v", err)
	}
}

// Once the caller erases the key buffer the identity is useless: there is
// no second copy inside it.
func TestSecretIdentityHoldsNoCopyOfTheKey(t *testing.T) {
	id := newIdentity(t)
	mine, secret := testSecretIdentity(t, id)
	enc, _ := encryptValue("x", id.Recipient())
	if _, err := decryptValue(enc, mine); err != nil {
		t.Fatal(err)
	}
	wipe(secret[:])
	if _, err := decryptValue(enc, mine); err == nil {
		t.Error("identity still decrypts after its key buffer was erased")
	}
}
