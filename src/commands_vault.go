package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"
)

func (a *app) vaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Protect the private key with a passphrase",
		Long: `Protect the private key with a passphrase.

A protected key file is the usual age identity file encrypted with a
passphrase in the standard age format, so it can still be copied to another
machine and used there, or with "age -d -i <key file>", by whoever knows
the passphrase. The passphrase is always asked for on the terminal.`,
	}
	cmd.AddCommand(a.vaultInitCmd(), a.vaultPasswdCmd())
	return cmd
}

// vaultKeyPath is the key file "vault init" works on: the resolved one, or
// key.txt in the config directory when there is none yet.
func (a *app) vaultKeyPath() string {
	if path, _, err := a.resolveKey(); err == nil {
		return path
	}
	return filepath.Join(getConfigPath(), keyFileName)
}

// writeProtectedKey encrypts identity with passphrase, checks that the
// result opens again, and only then replaces the key file.
func writeProtectedKey(path string, identity *age.X25519Identity, passphrase []byte) error {
	data, err := encryptKeyFile(identity, passphrase)
	if err != nil {
		return fmt.Errorf("encrypting key: %w", err)
	}
	check, err := decryptKeyFile(data, passphrase, path)
	if err != nil || check.String() != identity.String() {
		return errors.New("the protected key could not be verified; nothing was changed")
	}
	if err := writeFileAtomic(path, data); err != nil {
		return err
	}
	return writeFileAtomic(pubSidecarPath(path), []byte(identity.Recipient().String()+"\n"))
}

func (a *app) vaultInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create a passphrase-protected key, or protect the existing one",
		Long: `Create a passphrase-protected key, or protect the existing one.

The key file is the one kvage would use (--key, ./.kvage/key.txt,
AGE_KEY_FILE, or key.txt in the config directory). When it does not exist a
new key is generated. When it exists as a plain file it is replaced, in
place, by its passphrase-protected form: same key, same public key, nothing
to re-encrypt.

The public key is also written to "<key file>.pub" so values can be
encrypted without unlocking.

There is no way to recover a forgotten passphrase. Replacing the file does
not erase earlier copies of the plain key (backups, other machines, old
disk blocks).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			path := a.vaultKeyPath()
			var identity *age.X25519Identity

			data, err := os.ReadFile(path)
			switch {
			case errors.Is(err, os.ErrNotExist):
				identity, err = age.GenerateX25519Identity()
				if err != nil {
					return fmt.Errorf("generating key: %w", err)
				}
				fmt.Fprintf(a.errw, "Creating a new key in %s\n", path)
			case err != nil:
				return fmt.Errorf("reading key file: %w", err)
			case isEncryptedKey(data):
				return fmt.Errorf("%s is already passphrase-protected (use `kvage vault passwd` to change the passphrase)", path)
			default:
				identity, err = parseIdentityText(data, path)
				if err != nil {
					return err
				}
				fmt.Fprintf(a.errw, "Protecting the existing key %s\n", path)
			}

			pass, err := newPassphrase("New passphrase: ")
			if err != nil {
				return err
			}
			defer wipe(pass)
			if err := writeProtectedKey(path, identity, pass); err != nil {
				return err
			}
			fmt.Fprintf(a.errw, "Done. Public key: %s\n", identity.Recipient())
			return nil
		},
	}
}

func (a *app) vaultPasswdCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "passwd",
		Short: "Change the passphrase of the key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			kf, err := a.loadKeyFile()
			if err != nil {
				return err
			}
			if !kf.encrypted {
				return fmt.Errorf("%s is not passphrase-protected (use `kvage vault init`)", kf.path)
			}
			identity, err := a.askAndDecrypt(kf)
			if err != nil {
				return err
			}
			pass, err := newPassphrase("New passphrase: ")
			if err != nil {
				return err
			}
			defer wipe(pass)
			if err := writeProtectedKey(kf.path, identity, pass); err != nil {
				return err
			}
			// The file content changed, so an open session no longer
			// matches it.
			agentCall(&agentRequest{Op: "lock", KeyID: kf.id()})
			fmt.Fprintln(a.errw, "Passphrase changed.")
			return nil
		},
	}
}

func (a *app) unlockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unlock",
		Short: "Ask for the passphrase and keep the key unlocked for the session",
		Long: `Ask for the passphrase and hand the key to the session agent, a background
kvage process that keeps it in memory and decrypts for later commands until
"kvage lock", the configured inactivity timeout, logout or reboot.

With the default configuration this happens by itself the first time a
command needs the key.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			kf, err := a.loadKeyFile()
			if err != nil {
				return err
			}
			if !kf.encrypted {
				return fmt.Errorf("%s is not passphrase-protected: there is nothing to unlock (see `kvage vault init`)", kf.path)
			}
			cfg, err := a.userConfig()
			if err != nil {
				return err
			}
			if !agentSupported {
				return errors.New("sessions are not supported on this platform: the passphrase is asked for on every command")
			}
			if cfg.sessionMode() == sessionModeAlways {
				return errors.New("session.mode is \"always\" in config.yaml: the passphrase is asked for on every command")
			}
			if _, err := agentRecipient(kf.id()); err == nil {
				fmt.Fprintln(a.errw, "Already unlocked.")
				return nil
			}
			identity, err := a.askAndDecrypt(kf)
			if err != nil {
				return err
			}
			if err := a.addToAgent(kf, identity, cfg); err != nil {
				return fmt.Errorf("opening the session: %w", err)
			}
			fmt.Fprintln(a.errw, "Unlocked.")
			return nil
		},
	}
}

func (a *app) lockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Forget every unlocked key and stop the session agent",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := agentCall(&agentRequest{Op: "lock"})
			if errors.Is(err, errAgentDown) {
				fmt.Fprintln(a.errw, "Already locked.")
				return nil
			}
			if err != nil {
				// An agent that refuses this binary (kvage was replaced
				// since it started) is stopped through its PID file.
				if stopAgentByPID() != nil {
					return err
				}
			}
			fmt.Fprintln(a.errw, "Locked.")
			return nil
		},
	}
}

func (a *app) statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show which files are in use and whether the key is unlocked",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			w := a.out
			store, storeSource := a.resolveStore()
			fmt.Fprintf(w, "Store:       %s (%s%s)\n", store, storeSource, missingNote(store))

			if path, source, ok := a.resolveStoreRecipients(); ok {
				fmt.Fprintf(w, "Recipients:  %s (%s)\n", path, source)
			} else {
				fmt.Fprintln(w, "Recipients:  own key only (no public-keys.txt next to the store)")
			}

			cfg, cfgErr := a.userConfig()
			fmt.Fprintf(w, "Config:      %s%s\n", userConfigPath(), missingNote(userConfigPath()))
			if cfgErr != nil {
				fmt.Fprintf(w, "             invalid: %v\n", cfgErr)
				cfg = &userConfig{}
			}

			kf, err := a.loadKeyFile()
			if err != nil {
				fmt.Fprintf(w, "Key:         %v\n", err)
				return nil
			}
			fmt.Fprintf(w, "Key:         %s (%s)\n", kf.path, kf.source)
			if !kf.encrypted {
				fmt.Fprintln(w, "Protection:  none, plain file (run `kvage vault init` to add a passphrase)")
				return nil
			}
			fmt.Fprintln(w, "Protection:  passphrase")

			switch {
			case !agentSupported:
				fmt.Fprintln(w, "Session:     not supported on this platform, the passphrase is asked for every time")
				return nil
			case cfg.sessionMode() == sessionModeAlways:
				fmt.Fprintln(w, "Session:     disabled (session.mode: always), the passphrase is asked for every time")
				return nil
			}

			resp, err := agentCall(&agentRequest{Op: "status"})
			if errors.Is(err, errAgentDown) {
				fmt.Fprintln(w, "Session:     locked")
				return nil
			}
			if err != nil {
				fmt.Fprintf(w, "Session:     agent unreachable: %v\n", err)
				return nil
			}
			state := "locked"
			for _, k := range resp.Keys {
				if k.KeyID == kf.id() {
					state = "unlocked since " + k.Since.Local().Format(time.DateTime)
				}
			}
			fmt.Fprintf(w, "Session:     %s\n", state)
			timeout := "none (until `kvage lock`, logout or reboot)"
			if resp.Timeout != "" {
				timeout = resp.Timeout + " without use"
			}
			fmt.Fprintf(w, "Agent:       pid %d, %s, timeout %s\n", resp.PID, resp.Version, timeout)
			var others []string
			for _, k := range resp.Keys {
				if k.KeyID != kf.id() {
					others = append(others, k.Path)
				}
			}
			sort.Strings(others)
			for _, p := range others {
				fmt.Fprintf(w, "             also unlocked: %s\n", p)
			}
			for _, h := range resp.Hardening {
				fmt.Fprintf(w, "             %s\n", h)
			}
			return nil
		},
	}
}

func missingNote(path string) string {
	if !fileExists(path) {
		return ", not created yet"
	}
	return ""
}

// agentCmd is the session agent itself. It is started by kvage, not by the
// user.
func (a *app) agentCmd() *cobra.Command {
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:    "agent",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAgent(timeout, a.out)
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", 0, "lock after this long without use")
	return cmd
}
