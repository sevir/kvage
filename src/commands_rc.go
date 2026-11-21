package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const defaultRCFile = ".kvagerc"

func (a *app) rcCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rc [file]",
		Short: "Print the variables of an encrypted .kvagerc as shell exports",
		Long: `Decrypt a .kvagerc file (./.kvagerc by default) and print the environment
variables it defines as single-quoted shell exports. This is what the
"kvage shellrc" hook evaluates.

The decrypted text is never executed. Only variable assignments are
accepted (NAME=value, export NAME=value, comments, shell quoting, $VAR and
${VAR} references); any other line is ignored with a warning. Variables
that change how programs are found or loaded (PATH, LD_*, PROMPT_COMMAND,
...) are not set unless listed under rc.allow in the kvage config.yaml.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			file := defaultRCFile
			if len(args) == 1 {
				file = args[0]
			}
			encrypted, err := os.ReadFile(file)
			if err != nil {
				return fmt.Errorf("reading %s: %w", file, err)
			}

			var allow []string
			if cfg, err := loadUserConfig(); err != nil {
				a.warnf("%v; using the default settings", err)
			} else {
				allow = cfg.RC.Allow
			}

			identity, err := a.identity()
			if err != nil {
				return err
			}
			text, err := decryptValue(string(encrypted), identity)
			if err != nil {
				return fmt.Errorf("decrypting %s: %w", file, err)
			}

			vars, warnings := parseRC(text, os.LookupEnv, allow)
			for _, w := range warnings {
				a.warnf("%s: %s", file, w)
			}
			for _, v := range vars {
				fmt.Fprintf(a.out, "export %s=%s\n", v.Name, shellQuote(v.Value))
			}
			return nil
		},
	}
}

func (a *app) rekeyCmd() *cobra.Command {
	var rcFile string
	var noStore bool
	cmd := &cobra.Command{
		Use:   "rekey",
		Short: "Re-encrypt every value for the current recipients",
		Long: `Decrypt every value of the store with the own private key and encrypt it
again for the current recipients: the public-keys.txt next to the store,
or the own key when there is none. Run it after adding or removing a
recipient.

With --rc a .kvagerc file is re-encrypted too (./.kvagerc when no path is
given), for ./.kvage/public-keys.txt or else the list of the store. Use
--no-store to re-encrypt only that file.

Nothing is written unless everything could be decrypted. Removing a
recipient does not revoke what they could already read: rotate the secrets
themselves when someone must lose access.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if noStore && rcFile == "" {
				return errors.New("--no-store needs --rc")
			}
			identity, err := a.identity()
			if err != nil {
				return err
			}

			if !noStore {
				storePath := a.storePath()
				kv, err := loadStore(storePath)
				if err != nil {
					return err
				}
				recipients, err := a.storeRecipients()
				if err != nil {
					return err
				}
				out := &KeyValue{Data: make(map[string]string, len(kv.Data))}
				failed := 0
				for _, k := range kv.sortedKeys(nil) {
					plain, err := decryptValue(kv.Data[k], identity)
					if err != nil {
						fmt.Fprintf(a.errw, "Error: decrypting %s: %v\n", k, err)
						failed++
						continue
					}
					enc, err := encryptValue(plain, recipients...)
					if err != nil {
						return fmt.Errorf("encrypting %s: %w", k, err)
					}
					out.Data[k] = enc
				}
				if failed > 0 {
					return fmt.Errorf("%d value(s) could not be decrypted; the store was not modified", failed)
				}
				if err := saveStore(storePath, out); err != nil {
					return err
				}
				fmt.Fprintf(a.errw, "Re-encrypted %d value(s) in %s for %d recipient(s)\n", len(out.Data), storePath, len(recipients))
			}

			if rcFile != "" {
				encrypted, err := os.ReadFile(rcFile)
				if err != nil {
					return fmt.Errorf("reading %s: %w", rcFile, err)
				}
				plain, err := decryptValue(string(encrypted), identity)
				if err != nil {
					return fmt.Errorf("decrypting %s: %w", rcFile, err)
				}
				recipients, err := a.streamRecipients()
				if err != nil {
					return err
				}
				enc, err := encryptValue(plain, recipients...)
				if err != nil {
					return fmt.Errorf("encrypting %s: %w", rcFile, err)
				}
				if err := writeFileAtomic(rcFile, []byte(enc)); err != nil {
					return err
				}
				fmt.Fprintf(a.errw, "Re-encrypted %s for %d recipient(s)\n", rcFile, len(recipients))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&rcFile, "rc", "", "also re-encrypt this .kvagerc file (./.kvagerc when no path is given)")
	cmd.Flags().Lookup("rc").NoOptDefVal = defaultRCFile
	cmd.Flags().BoolVar(&noStore, "no-store", false, "do not re-encrypt the store (with --rc)")
	return cmd
}
