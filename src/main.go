package main

import (
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/spf13/cobra"
)

//go:embed kvagerc.txt
var kvagerc string

// app carries the global flags and the standard streams of one invocation,
// so commands can be driven from tests.
type app struct {
	keyFile   string
	storeFile string
	in        io.Reader
	out       io.Writer
	errw      io.Writer
}

// errReported marks a failure whose details were already written to stderr.
var errReported = errors.New("")

func (a *app) warnf(format string, args ...any) {
	fmt.Fprintf(a.errw, "Warning: "+format+"\n", args...)
}

func newRootCmd(in io.Reader, out, errw io.Writer) *cobra.Command {
	a := &app{in: in, out: out, errw: errw}

	root := &cobra.Command{
		Use:           "kvage",
		Short:         "A simple key-value store command line tool",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetIn(in)
	root.SetOut(out)
	root.SetErr(errw)
	root.PersistentFlags().StringVarP(&a.keyFile, "key", "k", "", "path to the age key file")
	root.PersistentFlags().StringVarP(&a.storeFile, "file", "f", "", "path to the YAML store file")

	root.AddCommand(
		a.setCmd(),
		a.getCmd(),
		a.listCmd(),
		a.searchCmd(),
		a.rmCmd(),
		a.exportCmd(),
		a.generateKeyCmd(),
		a.versionCmd(),
		a.encryptCmd(),
		a.decryptCmd(),
		a.shellrcCmd(),
		a.rcCmd(),
		a.rekeyCmd(),
	)
	return root
}

func (a *app) versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(a.out, "Version: %s\n", Version)
		},
	}
}

// completeKeys offers the store key names for the first argument.
func (a *app) completeKeys(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	kv, err := loadStore(a.storePath())
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return kv.sortedKeys(nil), cobra.ShellCompDirectiveNoFileComp
}

func (a *app) setCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "set <key> [value]",
		Aliases: []string{"up"},
		Short:   "Save an encrypted key-value pair",
		Long: `Save an encrypted key-value pair, replacing any previous value.

When a public-keys.txt file exists next to the store, the value is
encrypted for every recipient listed in it and the private key is not
needed. Otherwise it is encrypted for the own key only.

Without a value argument the value is asked for without echo, or read from
standard input when it is not a terminal. Passing the value as an argument
still works, but it stays in the shell history.`,
		Args:              cobra.RangeArgs(1, 2),
		ValidArgsFunction: a.completeKeys,
		RunE: func(cmd *cobra.Command, args []string) error {
			storePath, storeSource := a.resolveStore()
			if _, keySource, err := a.resolveKey(); err == nil && keySource == sourceLocal && storeSource != sourceLocal {
				a.warnf("using the key in ./%s but the store %s: values saved now can only be read with that key", localDirName, storePath)
			}
			recipients, err := a.storeRecipients()
			if err != nil {
				return err
			}

			var value string
			if len(args) == 2 {
				value = args[1]
				a.warnf("the value was passed as an argument and may be kept in the shell history; use `kvage set %s` to be prompted for it", args[0])
			} else {
				value, err = a.readSecret(fmt.Sprintf("Value for %s: ", args[0]))
				if err != nil {
					return err
				}
			}

			kv, err := loadStore(storePath)
			if err != nil {
				return err
			}
			encrypted, err := encryptValue(value, recipients...)
			if err != nil {
				return fmt.Errorf("encrypting value: %w", err)
			}
			kv.Data[args[0]] = encrypted
			return saveStore(storePath, kv)
		},
	}
}

func (a *app) getCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "get <key>",
		Short:             "Retrieve and decrypt a value by key",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeKeys,
		RunE: func(cmd *cobra.Command, args []string) error {
			kv, err := loadStore(a.storePath())
			if err != nil {
				return err
			}
			val, ok := kv.Data[args[0]]
			if !ok {
				return fmt.Errorf("key '%s' not found", args[0])
			}
			identity, err := a.identity()
			if err != nil {
				return err
			}
			decrypted, err := decryptValue(val, identity)
			if err != nil {
				return fmt.Errorf("decrypting value: %w", err)
			}
			fmt.Fprintln(a.out, decrypted)
			return nil
		},
	}
}

// decryptEach decrypts the given keys in order and calls fn for each value.
// Values that cannot be decrypted are reported on stderr and make the
// command fail once the rest has been processed.
func (a *app) decryptEach(kv *KeyValue, keys []string, fn func(key, value string)) error {
	if len(keys) == 0 {
		return nil
	}
	identity, err := a.identity()
	if err != nil {
		return err
	}
	failed := 0
	for _, k := range keys {
		decrypted, err := decryptValue(kv.Data[k], identity)
		if err != nil {
			fmt.Fprintf(a.errw, "Error: decrypting %s: %v\n", k, err)
			failed++
			continue
		}
		fn(k, decrypted)
	}
	if failed > 0 {
		fmt.Fprintf(a.errw, "Error: %d value(s) could not be decrypted\n", failed)
		return errReported
	}
	return nil
}

func (a *app) listCmd() *cobra.Command {
	var filter string
	var reveal bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all keys with their values masked",
		Long: `List all keys with their values masked.

A masked value shows at most two characters at each end around a
fixed-width mask, so it does not reveal its length. Use --reveal to print
the full values.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			kv, err := loadStore(a.storePath())
			if err != nil {
				return err
			}
			keys := kv.sortedKeys(func(k string) bool {
				return filter == "" || strings.Contains(k, filter)
			})
			return a.decryptEach(kv, keys, func(k, v string) {
				if !reveal {
					v = maskValue(v)
				}
				fmt.Fprintf(a.out, "%s: %s\n", k, v)
			})
		},
	}
	cmd.Flags().StringVar(&filter, "filter", "", "filter keys containing this text")
	cmd.Flags().BoolVar(&reveal, "reveal", false, "print the full values instead of masked ones")
	return cmd
}

// keyMatcher matches key names against pattern, ignoring case: as a glob
// when it has glob metacharacters, as a substring otherwise.
func keyMatcher(pattern string) (func(string) bool, error) {
	p := strings.ToLower(pattern)
	if !strings.ContainsAny(p, "*?[") {
		return func(k string) bool { return strings.Contains(strings.ToLower(k), p) }, nil
	}
	if _, err := path.Match(p, ""); err != nil {
		return nil, fmt.Errorf("invalid pattern %q: %w", pattern, err)
	}
	return func(k string) bool {
		ok, _ := path.Match(p, strings.ToLower(k))
		return ok
	}, nil
}

func (a *app) searchCmd() *cobra.Command {
	var byValue bool
	cmd := &cobra.Command{
		Use:   "search [pattern]",
		Short: "Search keys by name, or by value with --value",
		Long: `Search keys by name without decrypting anything. The pattern is matched
case-insensitively, as a substring or as a glob (*, ?, [...]).

With --value the text to look for is never taken from the command line: it
is asked for without echo, or read from standard input when it is not a
terminal. Values are decrypted in memory and the keys whose value contains
the text are listed with the value masked, as in "list". A pattern can
still be given to restrict the keys that are searched.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !byValue && len(args) == 0 {
				return errors.New("a key pattern is required (or use --value)")
			}
			var match func(string) bool
			if len(args) == 1 {
				m, err := keyMatcher(args[0])
				if err != nil {
					return err
				}
				match = m
			}

			var needle string
			if byValue {
				n, err := a.readSecret("Value to search for: ")
				if err != nil {
					return err
				}
				needle = n
			}

			kv, err := loadStore(a.storePath())
			if err != nil {
				return err
			}
			keys := kv.sortedKeys(match)
			if !byValue {
				for _, k := range keys {
					fmt.Fprintln(a.out, k)
				}
				return nil
			}
			return a.decryptEach(kv, keys, func(k, v string) {
				if strings.Contains(v, needle) {
					fmt.Fprintf(a.out, "%s: %s\n", k, maskValue(v))
				}
			})
		},
	}
	cmd.Flags().BoolVar(&byValue, "value", false, "search inside the decrypted values (the text is prompted for)")
	return cmd
}

func (a *app) rmCmd() *cobra.Command {
	return &cobra.Command{
		Use:               "rm <key>",
		Short:             "Delete a key",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: a.completeKeys,
		RunE: func(cmd *cobra.Command, args []string) error {
			storePath := a.storePath()
			kv, err := loadStore(storePath)
			if err != nil {
				return err
			}
			if _, ok := kv.Data[args[0]]; !ok {
				return fmt.Errorf("key '%s' not found", args[0])
			}
			delete(kv.Data, args[0])
			return saveStore(storePath, kv)
		},
	}
}

func (a *app) generateKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "generate-key",
		Short: "Generate a new age key pair",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return generateKeyPair(a.out)
		},
	}
}

func (a *app) exportCmd() *cobra.Command {
	var filter string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export keys and values as shell export statements",
		Long: `Export keys and values as shell export statements.

Names are upper-cased and values are single-quoted, so the output is safe
to eval. Keys whose name is not a valid shell identifier are skipped with
a warning.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			kv, err := loadStore(a.storePath())
			if err != nil {
				return err
			}
			keys := kv.sortedKeys(func(k string) bool {
				if filter != "" && !strings.Contains(k, filter) {
					return false
				}
				if !validEnvName(strings.ToUpper(k)) {
					a.warnf("skipping %q: not a valid shell variable name", k)
					return false
				}
				return true
			})
			return a.decryptEach(kv, keys, func(k, v string) {
				fmt.Fprintf(a.out, "export %s=%s\n", strings.ToUpper(k), shellQuote(v))
			})
		},
	}
	cmd.Flags().StringVar(&filter, "filter", "", "filter keys containing this text")
	return cmd
}

func (a *app) encryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt text from stdin for the own key or the recipients list",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			recipients, err := a.streamRecipients()
			if err != nil {
				return err
			}
			input, err := io.ReadAll(a.in)
			if err != nil {
				return fmt.Errorf("reading stdin: %w", err)
			}
			encrypted, err := encryptValue(string(input), recipients...)
			if err != nil {
				return fmt.Errorf("encrypting input: %w", err)
			}
			_, err = io.WriteString(a.out, encrypted)
			return err
		},
	}
}

func (a *app) decryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt text from stdin using the private key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			identity, err := a.identity()
			if err != nil {
				return err
			}
			input, err := io.ReadAll(a.in)
			if err != nil {
				return fmt.Errorf("reading stdin: %w", err)
			}
			decrypted, err := decryptValue(string(input), identity)
			if err != nil {
				return fmt.Errorf("decrypting input: %w", err)
			}
			_, err = io.WriteString(a.out, decrypted)
			return err
		},
	}
}

func (a *app) shellrcCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "shellrc",
		Short: "Inserts the possibility to use .kvagerc files in each directory",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprint(a.out, kvagerc)
		},
	}
}

func main() {
	if err := newRootCmd(os.Stdin, os.Stdout, os.Stderr).Execute(); err != nil {
		if !errors.Is(err, errReported) {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		}
		os.Exit(1)
	}
}
