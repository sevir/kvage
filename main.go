package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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

var keyFile string

func getKeyFromFile(keyPath string) (*age.X25519Identity, error) {
	content, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	if len(lines) < 3 {
		return nil, fmt.Errorf("invalid key file format")
	}

	identity, err := age.ParseX25519Identity(lines[2])
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return identity, nil
}

func getPrivateKey() (*age.X25519Identity, error) {
	keyPath := os.Getenv("AGE_KEY_FILE")
	if keyPath == "" {
		keyPath = keyFile
	}
	if keyPath == "" {
		return nil, fmt.Errorf("no key file specified")
	}
	return getKeyFromFile(keyPath)
}

func encryptValue(value string, identity *age.X25519Identity) (string, error) {
	recipient := identity.Recipient()
	buf := &bytes.Buffer{}
	w, err := age.Encrypt(buf, recipient)
	if err != nil {
		return "", err
	}

	if _, err := io.WriteString(w, value); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func decryptValue(encryptedValue string, identity *age.X25519Identity) (string, error) {
	r, err := age.Decrypt(strings.NewReader(encryptedValue), identity)
	if err != nil {
		return "", err
	}

	decrypted, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

var setCmd = &cobra.Command{
	Use:   "set [key] [value]",
	Short: "Save an encrypted key-value pair",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		identity, err := getPrivateKey()
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
		identity, err := getPrivateKey()
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
		identity, err := getPrivateKey()
		if err != nil {
			fmt.Printf("Error getting private key: %v\n", err)
			return
		}

		kv := loadData()
		for k, v := range kv.Data {
			decrypted, err := decryptValue(v, identity)
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
		privateKeyContent := fmt.Sprintf("# created: %s\n# public key: %s\n%s",
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
	rootCmd.PersistentFlags().StringVarP(&keyFile, "key", "k", "", "path to the age key file")
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
