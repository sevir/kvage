package main

import (
	"os"
	"path/filepath"
	"runtime"
)

// getConfigPath returns the per-user kvage configuration directory.
// The locations are the same ones v1.11.0 used, so existing stores are found
// without migration.
func getConfigPath() string {
	var configPath string
	switch runtime.GOOS {
	case "windows":
		configPath = os.Getenv("APPDATA")
	case "darwin":
		configPath = filepath.Join(os.Getenv("HOME"), "Library", "Application Support")
	case "linux":
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			configPath = filepath.Join(home, ".config")
		} else {
			configPath = "/etc"
		}
	default:
		configPath = "/etc"
	}
	return filepath.Join(configPath, "kvage")
}
