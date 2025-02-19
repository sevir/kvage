package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type KeyValue struct {
	Data map[string]string `yaml:"data"`
}

var rootCmd = &cobra.Command{
	Use:   "kv",
	Short: "A simple key-value store CLI",
}

var setCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Save a key-value pair",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		kv := loadData()
		kv.Data[args[0]] = args[1]
		saveData(kv)
	},
}

var getCmd = &cobra.Command{
	Use:   "get [key]",
	Short: "Retrieve a value by key",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		kv := loadData()
		if val, ok := kv.Data[args[0]]; ok {
			fmt.Println(val)
		} else {
			fmt.Printf("Key '%s' not found\n", args[0])
		}
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all keys with their values",
	Run: func(cmd *cobra.Command, args []string) {
		kv := loadData()
		for k, v := range kv.Data {
			fmt.Printf("%s: %s\n", k, v)
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
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			fmt.Printf("Error generating key pair: %v\n", err)
			return
		}

		// Create keys directory if it doesn't exist
		keysDir := "keys"
		if err := os.MkdirAll(keysDir, 0700); err != nil {
			fmt.Printf("Error creating keys directory: %v\n", err)
			return
		}

		// Format private key content with creation time and public key info
		creationTime := time.Now().Format(time.RFC3339)
		publicKey := identity.Recipient().String()
		privateKeyContent := fmt.Sprintf("# Created: %s\n# Public key: %s\n%s",
			creationTime,
			publicKey,
			identity.String())

		// Save private key
		privKeyPath := filepath.Join(keysDir, "key.txt")
		if err := os.WriteFile(privKeyPath, []byte(privateKeyContent), 0600); err != nil {
			fmt.Printf("Error saving private key: %v\n", err)
			return
		}

		fmt.Printf("Key pairs saved to: %s\n", privKeyPath)
	},
}

func init() {
	rootCmd.AddCommand(setCmd)
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(rmCmd)
	rootCmd.AddCommand(generateKeyCmd)
}

func loadData() *KeyValue {
	kv := &KeyValue{Data: make(map[string]string)}
	data, err := os.ReadFile("store.yaml")
	if err == nil {
		yaml.Unmarshal(data, kv)
	}
	return kv
}

func saveData(kv *KeyValue) {
	data, err := yaml.Marshal(kv)
	if err != nil {
		fmt.Printf("Error saving data: %v\n", err)
		return
	}
	err = os.WriteFile("store.yaml", data, 0644)
	if err != nil {
		fmt.Printf("Error writing file: %v\n", err)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
