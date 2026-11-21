//go:build darwin

package main

import "errors"

var errTPMUnavailable = errors.New("no usable TPM")

func newTPMSlot(*[x25519Size]byte) (keySlot, error) {
	return nil, errTPMUnavailable
}
