package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// userConfig is <config dir>/config.yaml. It is only ever read from the
// user's own config directory, never from a project's .kvage directory:
// a repository must not be able to relax the user's safety settings.
type userConfig struct {
	RC struct {
		// Allow lists otherwise blocked variable names that .kvagerc files
		// may set. An entry ending in "*" matches a prefix.
		Allow []string `yaml:"allow"`
	} `yaml:"rc"`
}

func userConfigPath() string {
	return filepath.Join(getConfigPath(), userConfigFileName)
}

// loadUserConfig reads the user configuration. A missing file means defaults.
func loadUserConfig() (*userConfig, error) {
	cfg := &userConfig{}
	data, err := os.ReadFile(userConfigPath())
	if errors.Is(err, fs.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", userConfigPath(), err)
	}
	return cfg, nil
}
