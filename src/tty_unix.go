//go:build !windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// ttyPassphrase reads a passphrase from the controlling terminal, not from
// stdin, so commands that take their data on stdin can still ask for it.
func ttyPassphrase(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("a passphrase is needed but there is no terminal to ask for it: %w", err)
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	pass, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %w", err)
	}
	return pass, nil
}
