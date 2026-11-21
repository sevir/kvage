//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// ttyPassphrase reads a passphrase from the console, not from stdin, so
// commands that take their data on stdin can still ask for it.
func ttyPassphrase(prompt string) ([]byte, error) {
	in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("a passphrase is needed but there is no console to ask for it: %w", err)
	}
	defer in.Close()
	out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("a passphrase is needed but there is no console to ask for it: %w", err)
	}
	defer out.Close()
	fmt.Fprint(out, prompt)
	pass, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(out)
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %w", err)
	}
	return pass, nil
}
