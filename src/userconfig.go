package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

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

	Session struct {
		// Mode is "session" (default: after the first passphrase prompt the
		// key stays unlocked in a background agent until "kvage lock",
		// logout or reboot) or "always" (ask for the passphrase every time,
		// no agent).
		Mode string `yaml:"mode"`
		// Timeout locks the session after this long without use, e.g.
		// "30m". Empty or "0" means no timeout.
		Timeout string `yaml:"timeout"`
		// TPM is "auto" (default: on Linux, keep the unlocked key sealed in
		// the TPM when one is usable, otherwise in the agent's memory),
		// "off" (always in memory) or "require" (fail without a TPM).
		TPM string `yaml:"tpm"`
	} `yaml:"session"`

	Key struct {
		// WarnPlaintext controls the reminder printed when the private key
		// file is not passphrase-protected. Default true.
		WarnPlaintext *bool `yaml:"warn_plaintext"`
	} `yaml:"key"`
}

const (
	sessionModeSession = "session"
	sessionModeAlways  = "always"

	tpmModeAuto    = "auto"
	tpmModeOff     = "off"
	tpmModeRequire = "require"
)

// defaultTPMMode is the session.tpm value when the config does not set one.
// A variable so tests do not depend on the machine's TPM.
var defaultTPMMode = tpmModeAuto

func (c *userConfig) tpmMode() string {
	if c.Session.TPM == "" {
		return defaultTPMMode
	}
	return c.Session.TPM
}

func (c *userConfig) sessionMode() string {
	if c.Session.Mode == "" {
		return sessionModeSession
	}
	return c.Session.Mode
}

func (c *userConfig) sessionTimeout() (time.Duration, error) {
	if c.Session.Timeout == "" || c.Session.Timeout == "0" {
		return 0, nil
	}
	d, err := time.ParseDuration(c.Session.Timeout)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid session.timeout %q (use a duration such as 30m)", c.Session.Timeout)
	}
	return d, nil
}

func (c *userConfig) validate() error {
	switch c.sessionMode() {
	case sessionModeSession, sessionModeAlways:
	default:
		return fmt.Errorf("invalid session.mode %q (use session or always)", c.Session.Mode)
	}
	switch c.tpmMode() {
	case tpmModeAuto, tpmModeOff, tpmModeRequire:
	default:
		return fmt.Errorf("invalid session.tpm %q (use auto, off or require)", c.Session.TPM)
	}
	_, err := c.sessionTimeout()
	return err
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
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", userConfigPath(), err)
	}
	return cfg, nil
}
