package main

import (
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"
)

type KeyValue struct {
	Data map[string]string `yaml:"data"`
}

var keyFile string
var storeFile string

var rootCmd = &cobra.Command{
	Use:   "kvage",
	Short: "A simple key-value store command line tool",
}

var setCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Save an encrypted key-value pair",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {

		if keyFile == "" && os.Getenv("AGE_KEY_FILE") == "" {
			fmt.Fprintf(os.Stderr, "Error: no key file specified. Either use --key flag or set AGE_KEY_FILE environment variable\n")
			os.Exit(1)
		}

		identity, err := getPrivateKey(keyFile)
		if err != nil {
			fmt.Printf("Error getting private key: %v\n", err)
			return
		}

		encrypted, err := encryptValue(args[1], identity)
		if err != nil {
			fmt.Printf("Error encrypting value: %v\n", err)
			return
		}

		kv := loadData()
		kv.Data[args[0]] = encrypted
		saveData(kv)
	},
}

var getCmd = &cobra.Command{
	Use:   "get [key]",
	Short: "Retrieve and decrypt a value by key",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		identity, err := getPrivateKey(keyFile)
		if err != nil {
			fmt.Printf("Error getting private key: %v\n", err)
			return
		}

		kv := loadData()
		if val, ok := kv.Data[args[0]]; ok {
			decrypted, err := decryptValue(val, identity)
			if err != nil {
				fmt.Printf("Error decrypting value: %v\n", err)
				return
			}
			fmt.Println(decrypted)
		} else {
			fmt.Printf("Key '%s' not found\n", args[0])
		}
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all keys with their decrypted values",
	Run: func(cmd *cobra.Command, args []string) {
		identity, err := getPrivateKey(keyFile)
		if err != nil {
			fmt.Printf("Error getting private key: %v\n", err)
			return
		}

		kv := loadData()
		// Create a sorted slice of keys
		keys := make([]string, 0, len(kv.Data))
		for k := range kv.Data {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// Iterate over sorted keys
		for _, k := range keys {
			decrypted, err := decryptValue(kv.Data[k], identity)
			if err != nil {
				fmt.Printf("%s: <error decrypting: %v>\n", k, err)
				continue
			}
			fmt.Printf("%s: %s\n", k, decrypted)
		}
	},
}

var rmCmd = &cobra.Command{
	Use:   "rm [key]",
	Short: "Delete a key",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		kv := loadData()
		delete(kv.Data, args[0])
		saveData(kv)
	},
}

var generateKeyCmd = &cobra.Command{
	Use:   "generate-key",
	Short: "Generate a new age key pair",
	Run: func(cmd *cobra.Command, args []string) {
		if err := generateKeyPair(); err != nil {
			fmt.Println(err)
		}
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&keyFile, "key", "k", "", "path to the age key file")
	rootCmd.PersistentFlags().StringVarP(&storeFile, "file", "f", "", "path to the YAML store file")
	rootCmd.AddCommand(setCmd)
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(rmCmd)
	rootCmd.AddCommand(generateKeyCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
