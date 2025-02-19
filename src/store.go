package main

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func getStoreFile() string {
	// If store file is specified via flag, use it
	if storeFile != "" {
		return storeFile
	}

	// Check if file exists in current directory
	if _, err := os.Stat("kvage.yaml"); err == nil {
		return "kvage.yaml"
	}
	// Return config directory path
	return filepath.Join(getConfigPath(), "kvage.yaml")
}

func loadData() *KeyValue {
	kv := &KeyValue{Data: make(map[string]string)}
	data, err := os.ReadFile(getStoreFile())
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

	storePath := getStoreFile()
	// Ensure directory exists
	err = os.MkdirAll(filepath.Dir(storePath), 0755)
	if err != nil {
		fmt.Printf("Error creating directory: %v\n", err)
		return
	}

	err = os.WriteFile(storePath, data, 0644)
	if err != nil {
		fmt.Printf("Error writing file: %v\n", err)
	}
}
