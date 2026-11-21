package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/term"
)

// maskFill is the fixed-width placeholder for hidden characters. Its length
// never depends on the value, so the output does not reveal the value size.
const maskFill = "****"

// maskValue hides a secret, keeping a short prefix and suffix as a hint:
// two characters on each side for 6 or more, one for 4 or 5, none below 4.
func maskValue(v string) string {
	r := []rune(v)
	keep := 0
	switch {
	case len(r) >= 6:
		keep = 2
	case len(r) >= 4:
		keep = 1
	}
	if keep == 0 {
		return maskFill
	}
	return printable(r[:keep]) + maskFill + printable(r[len(r)-keep:])
}

// printable replaces control and other non-printable runes so that a masked
// value always stays on one line.
func printable(r []rune) string {
	out := make([]rune, len(r))
	for i, c := range r {
		if unicode.IsPrint(c) {
			out[i] = c
		} else {
			out[i] = '?'
		}
	}
	return string(out)
}

// shellQuote wraps s in single quotes so a POSIX shell reads it literally.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validEnvName reports whether name can be used as a shell variable name.
func validEnvName(name string) bool {
	return envNameRe.MatchString(name)
}

// readSecret obtains a secret without putting it on the command line: with
// a terminal on stdin it prompts on stderr and reads without echo, otherwise
// it reads all of stdin and drops one trailing newline.
func (a *app) readSecret(prompt string) (string, error) {
	if f, ok := a.in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(a.errw, prompt)
		b, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(a.errw)
		if err != nil {
			return "", fmt.Errorf("reading input: %w", err)
		}
		return nonEmpty(string(b))
	}
	b, err := io.ReadAll(a.in)
	if err != nil {
		return "", fmt.Errorf("reading stdin: %w", err)
	}
	s := strings.TrimSuffix(string(b), "\n")
	s = strings.TrimSuffix(s, "\r")
	return nonEmpty(s)
}

func nonEmpty(s string) (string, error) {
	if s == "" {
		return "", errors.New("empty input")
	}
	return s, nil
}
