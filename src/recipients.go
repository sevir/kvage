package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"filippo.io/age"
)

// parseRecipientsFile reads a public-keys.txt: one age recipient per line,
// blank lines and "#" comments ignored, an optional " # comment" after a
// recipient allowed. An existing file with no recipients is an error, so a
// truncated list never silently narrows or widens who can read the data.
func parseRecipientsFile(path string) ([]age.Recipient, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading recipients: %w", err)
	}
	defer f.Close()

	var recipients []age.Recipient
	seen := make(map[string]bool)
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parsed, err := age.ParseRecipients(strings.NewReader(line))
		if err != nil || len(parsed) != 1 {
			return nil, fmt.Errorf("%s line %d: not a valid age recipient", path, n)
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		recipients = append(recipients, parsed[0])
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading recipients: %w", err)
	}
	if len(recipients) == 0 {
		return nil, fmt.Errorf("%s contains no recipients", path)
	}
	return recipients, nil
}

func recipientString(r age.Recipient) string {
	if s, ok := r.(fmt.Stringer); ok {
		return s.String()
	}
	return ""
}

// recipientsFor returns who to encrypt for. With a recipients file the data
// is encrypted for everyone listed and the private key is not needed; a
// warning is printed when the own public key is known and not listed.
// Without a file the only recipient is the own key, as in v1.11.0.
func (a *app) recipientsFor(path string, hasFile bool) ([]age.Recipient, error) {
	if !hasFile {
		own, err := a.ownRecipient()
		if err != nil {
			return nil, err
		}
		return []age.Recipient{own}, nil
	}

	recipients, err := parseRecipientsFile(path)
	if err != nil {
		return nil, err
	}
	if own, err := a.ownRecipientQuiet(); err == nil && own != nil {
		listed := false
		for _, r := range recipients {
			if recipientString(r) == own.String() {
				listed = true
				break
			}
		}
		if !listed {
			a.warnf("your own public key (%s) is not in %s: you will not be able to decrypt what is encrypted now", own, path)
		}
	}
	return recipients, nil
}

func (a *app) storeRecipients() ([]age.Recipient, error) {
	path, _, ok := a.resolveStoreRecipients()
	return a.recipientsFor(path, ok)
}

func (a *app) streamRecipients() ([]age.Recipient, error) {
	path, _, ok := a.resolveStreamRecipients()
	return a.recipientsFor(path, ok)
}
