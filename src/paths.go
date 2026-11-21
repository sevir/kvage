package main

import (
	"errors"
	"os"
	"path/filepath"
)

// File names kvage looks for at each level.
const (
	localDirName       = ".kvage"
	storeFileName      = "kvage.yaml"
	recipientsFileName = "public-keys.txt"
	keyFileName        = "key.txt"
	userConfigFileName = "config.yaml"
)

// Where a resolved file came from. Used by warnings and by "kvage status".
const (
	sourceFlag   = "flag"
	sourceLocal  = "./" + localDirName
	sourceCwd    = "current directory"
	sourceEnv    = "AGE_KEY_FILE"
	sourceConfig = "config directory"
	sourceStore  = "next to the store"
)

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// localDir returns ./.kvage when it exists in the current directory. Parent
// directories are deliberately not searched.
func localDir() (string, bool) {
	info, err := os.Stat(localDirName)
	if err != nil || !info.IsDir() {
		return "", false
	}
	return localDirName, true
}

// resolveStore picks the store file. Each kvage file is resolved on its own:
// a level that does not have the file falls through to the next one.
//
//	--file > ./.kvage/kvage.yaml > ./kvage.yaml > <config dir>/kvage.yaml
func (a *app) resolveStore() (path, source string) {
	if a.storeFile != "" {
		return a.storeFile, sourceFlag
	}
	if dir, ok := localDir(); ok {
		if p := filepath.Join(dir, storeFileName); fileExists(p) {
			return p, sourceLocal
		}
	}
	if fileExists(storeFileName) {
		return storeFileName, sourceCwd
	}
	return filepath.Join(getConfigPath(), storeFileName), sourceConfig
}

func (a *app) storePath() string {
	p, _ := a.resolveStore()
	return p
}

// resolveKey picks the private key file.
//
//	--key > ./.kvage/key.txt > AGE_KEY_FILE > <config dir>/key.txt
func (a *app) resolveKey() (path, source string, err error) {
	if a.keyFile != "" {
		return a.keyFile, sourceFlag, nil
	}
	if dir, ok := localDir(); ok {
		if p := filepath.Join(dir, keyFileName); fileExists(p) {
			return p, sourceLocal, nil
		}
	}
	if p := os.Getenv("AGE_KEY_FILE"); p != "" {
		return p, sourceEnv, nil
	}
	if p := filepath.Join(getConfigPath(), keyFileName); fileExists(p) {
		return p, sourceConfig, nil
	}
	return "", "", errors.New("no key file found: use the --key flag, set the AGE_KEY_FILE environment variable, or place key.txt in ./.kvage or in the kvage config directory")
}

// resolveStoreRecipients picks the recipients list used when writing to the
// store. The list is tied to the store it protects: only a public-keys.txt
// in the same directory as the store is used, so entering a directory can
// never change who the values of another store are encrypted for.
func (a *app) resolveStoreRecipients() (path, source string, ok bool) {
	store, storeSource := a.resolveStore()
	p := filepath.Join(filepath.Dir(store), recipientsFileName)
	if !fileExists(p) {
		return "", "", false
	}
	if storeSource == sourceFlag {
		storeSource = sourceStore
	}
	return p, storeSource, true
}

// resolveStreamRecipients picks the recipients list for data that does not
// live in the store ("encrypt", .kvagerc files): ./.kvage/public-keys.txt
// first, then the list of the resolved store.
func (a *app) resolveStreamRecipients() (path, source string, ok bool) {
	if a.storeFile == "" {
		if dir, isDir := localDir(); isDir {
			if p := filepath.Join(dir, recipientsFileName); fileExists(p) {
				return p, sourceLocal, true
			}
		}
	}
	return a.resolveStoreRecipients()
}
