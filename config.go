package main

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
)

func getConfigPath() string {
	var configPath string
	switch runtime.GOOS {
	case "windows":
		configPath = os.Getenv("APPDATA") // Carpeta AppData/Roaming en Windows
	case "darwin":
		configPath = filepath.Join(os.Getenv("HOME"), "Library", "Application Support") // MacOS
	case "linux":
		usr, err := user.Current()
		if err == nil {
			configPath = filepath.Join(usr.HomeDir, ".config") // Linux estándar
		} else {
			configPath = "/etc" // Alternativa si no se obtiene el usuario
		}
	default:
		configPath = "/etc"
	}
	return filepath.Join(configPath, "kvage")
}
