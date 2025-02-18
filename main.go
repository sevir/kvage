package main

import (
	"fmt"
	"os"

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

var upCmd = &cobra.Command{
	Use:   "up [key] [value]",
	Short: "Update a key-value pair",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		kv := loadData()
		if _, ok := kv.Data[args[0]]; ok {
			kv.Data[args[0]] = args[1]
			saveData(kv)
		} else {
			fmt.Printf("Key '%s' not found\n", args[0])
		}
	},
}

func init() {
	rootCmd.AddCommand(setCmd)
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(rmCmd)
	rootCmd.AddCommand(upCmd)
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
