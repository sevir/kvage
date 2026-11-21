package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// KeyValue is the on-disk store: a YAML document with a single "data" map
// from key name to an age-encrypted (binary) value.
type KeyValue struct {
	Data map[string]string `yaml:"data"`
}

// sortedKeys returns the store keys accepted by match, sorted.
func (kv *KeyValue) sortedKeys(match func(string) bool) []string {
	keys := make([]string, 0, len(kv.Data))
	for k := range kv.Data {
		if match == nil || match(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// loadStore reads the store. A missing file is an empty store; any other
// read or parse failure is an error, so a damaged file is never silently
// replaced by an empty one.
func loadStore(path string) (*KeyValue, error) {
	kv := &KeyValue{}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("reading store: %w", err)
	default:
		if err := yaml.Unmarshal(data, kv); err != nil {
			return nil, fmt.Errorf("parsing store %s: %w", path, err)
		}
	}
	if kv.Data == nil {
		kv.Data = make(map[string]string)
	}
	return kv, nil
}

// saveStore writes the store atomically (temporary file plus rename).
func saveStore(path string, kv *KeyValue) error {
	data, err := yaml.Marshal(kv)
	if err != nil {
		return fmt.Errorf("encoding store: %w", err)
	}
	return writeFileAtomic(path, data)
}

// writeFileAtomic replaces path with data through a temporary file in the
// same directory. New files are created 0600 inside 0700 directories; an
// existing file keeps its permissions, and a symlink keeps pointing at its
// (rewritten) target.
func writeFileAtomic(path string, data []byte) error {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating directory: %w", err)
	}

	mode := fs.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(mode); err != nil && mode != 0o600 {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return fail(err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
