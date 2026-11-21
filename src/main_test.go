package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
)

// env is an isolated kvage environment: temporary HOME, working directory
// and key. Nothing in it touches the real user configuration.
type env struct {
	t       *testing.T
	home    string
	work    string
	keyPath string
	id      *age.X25519Identity
}

// writeKey writes a throwaway identity in the layout v1.11.0 generated.
func writeKey(t *testing.T, path string) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf("# created: 2025-01-01T00:00:00Z\n# public key: %s\n%s", id.Recipient(), id)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return id
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, home: t.TempDir(), work: t.TempDir()}
	t.Setenv("HOME", e.home)
	t.Setenv("APPDATA", e.home)
	t.Setenv("AGE_KEY_FILE", "")
	t.Chdir(e.work)
	e.keyPath = filepath.Join(e.home, "key.txt")
	e.id = writeKey(t, e.keyPath)
	t.Setenv("AGE_KEY_FILE", e.keyPath)
	return e
}

// run executes kvage with stdin (not a terminal) and returns its streams.
func (e *env) run(stdin string, args ...string) (string, string, error) {
	e.t.Helper()
	var out, errw bytes.Buffer
	root := newRootCmd(strings.NewReader(stdin), &out, &errw)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), errw.String(), err
}

func (e *env) mustRun(stdin string, args ...string) (string, string) {
	e.t.Helper()
	out, errw, err := e.run(stdin, args...)
	if err != nil {
		e.t.Fatalf("kvage %v: %v (stderr: %s)", args, err, errw)
	}
	return out, errw
}

func (e *env) storeFile() string {
	return filepath.Join(getConfigPath(), "kvage.yaml")
}

func TestSetGetRoundTrip(t *testing.T) {
	e := newEnv(t)
	out, errw := e.mustRun("", "set", "api", "s3cret-value")
	if out != "" {
		t.Errorf("set printed to stdout: %q", out)
	}
	if !strings.Contains(errw, "shell history") {
		t.Errorf("no history warning for a value argument: %q", errw)
	}
	out, _ = e.mustRun("", "get", "api")
	if out != "s3cret-value\n" {
		t.Errorf("get = %q", out)
	}
}

func TestSetReadsValueFromStdin(t *testing.T) {
	e := newEnv(t)
	_, errw := e.mustRun("from stdin\n", "set", "k")
	if errw != "" {
		t.Errorf("unexpected stderr: %q", errw)
	}
	if out, _ := e.mustRun("", "get", "k"); out != "from stdin\n" {
		t.Errorf("get = %q", out)
	}

	// Only one trailing newline is dropped; inner newlines are kept.
	e.mustRun("a\nb\n\n", "set", "multi")
	if out, _ := e.mustRun("", "get", "multi"); out != "a\nb\n\n" {
		t.Errorf("multi-line get = %q", out)
	}

	if _, _, err := e.run("", "set", "empty"); err == nil {
		t.Error("empty stdin value was accepted")
	}
}

func TestUpIsAliasOfSet(t *testing.T) {
	e := newEnv(t)
	e.mustRun("one", "set", "k")
	e.mustRun("two", "up", "k")
	if out, _ := e.mustRun("", "get", "k"); out != "two\n" {
		t.Errorf("get = %q", out)
	}
}

func TestGetMissingKeyFails(t *testing.T) {
	e := newEnv(t)
	out, _, err := e.run("", "get", "nope")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("err = %v", err)
	}
	if out != "" {
		t.Errorf("stdout = %q", out)
	}
	if _, _, err := e.run("", "rm", "nope"); err == nil {
		t.Error("rm of a missing key succeeded")
	}
}

func TestRm(t *testing.T) {
	e := newEnv(t)
	e.mustRun("v", "set", "k")
	e.mustRun("", "rm", "k")
	if _, _, err := e.run("", "get", "k"); err == nil {
		t.Error("key still present after rm")
	}
}

func TestKeyFlagWinsOverEnvironment(t *testing.T) {
	e := newEnv(t)
	other := filepath.Join(e.home, "other.txt")
	writeKey(t, other)

	e.mustRun("v", "set", "k", "--key", other)
	// The environment key cannot read a value written for the --key one.
	if _, _, err := e.run("", "get", "k"); err == nil {
		t.Fatal("value was encrypted for AGE_KEY_FILE although --key was given")
	}
	if out, _ := e.mustRun("", "get", "k", "-k", other); out != "v\n" {
		t.Errorf("get = %q", out)
	}
}

func TestNoKeyConfigured(t *testing.T) {
	e := newEnv(t)
	t.Setenv("AGE_KEY_FILE", "")
	if _, _, err := e.run("v", "set", "k"); err == nil || !strings.Contains(err.Error(), "no key file") {
		t.Errorf("err = %v", err)
	}
}

func TestKeyFileLayouts(t *testing.T) {
	e := newEnv(t)
	e.mustRun("v", "set", "k")
	for name, content := range map[string]string{
		"bare":            e.id.String(),
		"trailing":        e.id.String() + "\n",
		"leading comment": "# note\n\n# another\n\n" + e.id.String() + "\n",
		"crlf":            "# created: x\r\n# public key: y\r\n" + e.id.String() + "\r\n",
	} {
		p := filepath.Join(e.home, "layout.txt")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, _, err := e.run("", "get", "k", "--key", p); err != nil || out != "v\n" {
			t.Errorf("%s: out=%q err=%v", name, out, err)
		}
	}

	bad := filepath.Join(e.home, "bad.txt")
	os.WriteFile(bad, []byte("not a key\n"), 0o600)
	if _, _, err := e.run("", "get", "k", "--key", bad); err == nil {
		t.Error("invalid key file accepted")
	}
	if _, _, err := e.run("", "get", "k", "--key", filepath.Join(e.home, "missing")); err == nil {
		t.Error("missing key file accepted")
	}
}

func TestCorruptStoreIsNotOverwritten(t *testing.T) {
	e := newEnv(t)
	store := filepath.Join(e.work, "store.yaml")
	garbage := []byte("data: [this is: not a map\n")
	if err := os.WriteFile(store, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"set", "k", "v", "-f", store},
		{"get", "k", "-f", store},
		{"list", "-f", store},
		{"rm", "k", "-f", store},
	} {
		if _, _, err := e.run("", args...); err == nil {
			t.Errorf("%v succeeded on a corrupt store", args)
		}
	}
	got, _ := os.ReadFile(store)
	if !bytes.Equal(got, garbage) {
		t.Errorf("corrupt store was modified: %q", got)
	}
}

func TestUnreadableStoreIsAnError(t *testing.T) {
	e := newEnv(t)
	// A directory in place of the file: reading fails, and not with ENOENT.
	store := filepath.Join(e.work, "store.yaml")
	if err := os.Mkdir(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.run("v", "set", "k", "-f", store); err == nil {
		t.Error("set succeeded although the store could not be read")
	}
}

func TestNewFilesArePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	e := newEnv(t)
	e.mustRun("v", "set", "k")
	if m := statMode(t, e.storeFile()); m != 0o600 {
		t.Errorf("new store mode = %o", m)
	}
	if m := statMode(t, filepath.Dir(e.storeFile())); m != 0o700 {
		t.Errorf("new config dir mode = %o", m)
	}
}

func TestExistingPermissionsAreKept(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	e := newEnv(t)
	dir := filepath.Join(e.work, "shared")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(dir, "s.yaml")
	if err := os.WriteFile(store, []byte("data: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.mustRun("v", "set", "k", "-f", store)
	if m := statMode(t, store); m != 0o644 {
		t.Errorf("existing store mode changed to %o", m)
	}
	if m := statMode(t, dir); m != 0o755 {
		t.Errorf("existing dir mode changed to %o", m)
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".*tmp*"))
	if len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestSymlinkedStoreKeepsItsLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	e := newEnv(t)
	target := filepath.Join(e.work, "real.yaml")
	if err := os.WriteFile(target, []byte("data: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(e.work, "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	e.mustRun("v", "set", "k", "-f", link)
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced by a regular file")
	}
	if out, _ := e.mustRun("", "get", "k", "-f", target); out != "v\n" {
		t.Errorf("target not updated: %q", out)
	}
}

func statMode(t *testing.T, p string) os.FileMode {
	t.Helper()
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestStoreInCurrentDirectoryIsPreferred(t *testing.T) {
	e := newEnv(t)
	e.mustRun("global", "set", "k")
	if err := os.WriteFile("kvage.yaml", []byte("data: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.mustRun("local", "set", "k")
	if out, _ := e.mustRun("", "get", "k"); out != "local\n" {
		t.Errorf("get = %q", out)
	}
	if out, _ := e.mustRun("", "get", "k", "-f", e.storeFile()); out != "global\n" {
		t.Errorf("global get = %q", out)
	}
}

func TestMaskValue(t *testing.T) {
	for in, want := range map[string]string{
		"":              "****",
		"a":             "****",
		"abc":           "****",
		"abcd":          "a****d",
		"abcde":         "a****e",
		"abcdef":        "ab****ef",
		"abcdefghijklm": "ab****lm",
		"ñandú-€uro":    "ña****ro",
		"\n\nxx\n\n":    "??****??",
	} {
		if got := maskValue(in); got != want {
			t.Errorf("maskValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestListMasksByDefault(t *testing.T) {
	e := newEnv(t)
	e.mustRun("supersecretvalue", "set", "long")
	e.mustRun("abcde", "set", "mid")
	e.mustRun("abc", "set", "short")

	out, _ := e.mustRun("", "list")
	want := "long: su****ue\nmid: a****e\nshort: ****\n"
	if out != want {
		t.Errorf("list = %q, want %q", out, want)
	}

	out, _ = e.mustRun("", "list", "--reveal")
	want = "long: supersecretvalue\nmid: abcde\nshort: abc\n"
	if out != want {
		t.Errorf("list --reveal = %q, want %q", out, want)
	}

	out, _ = e.mustRun("", "list", "--filter", "on")
	if out != "long: su****ue\n" {
		t.Errorf("list --filter = %q", out)
	}
}

func TestListReportsUndecryptableValues(t *testing.T) {
	e := newEnv(t)
	e.mustRun("mine", "set", "a")
	other := filepath.Join(e.home, "other.txt")
	writeKey(t, other)
	e.mustRun("theirs", "set", "b", "--key", other)

	out, errw, err := e.run("", "list", "--reveal")
	if !errors.Is(err, errReported) {
		t.Errorf("err = %v", err)
	}
	if out != "a: mine\n" {
		t.Errorf("stdout = %q", out)
	}
	if !strings.Contains(errw, "decrypting b") {
		t.Errorf("stderr = %q", errw)
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"plain":      `'plain'`,
		"":           `''`,
		`it's`:       `'it'\''s'`,
		`$(rm -rf)`:  `'$(rm -rf)'`,
		"a\"b`c`\\d": "'a\"b`c`\\d'",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExport(t *testing.T) {
	e := newEnv(t)
	e.mustRun(`pa"ss $(id) 'q'`, "set", "db_pass")
	e.mustRun("x", "set", "has-dash")
	e.mustRun("y", "set", "9lives")
	e.mustRun("z", "set", "token")

	out, errw := e.mustRun("", "export")
	want := "export DB_PASS='pa\"ss $(id) '\\''q'\\'''\nexport TOKEN='z'\n"
	if out != want {
		t.Errorf("export = %q, want %q", out, want)
	}
	for _, skipped := range []string{"has-dash", "9lives"} {
		if !strings.Contains(errw, skipped) {
			t.Errorf("no warning for %s: %q", skipped, errw)
		}
	}

	out, _ = e.mustRun("", "export", "--filter", "tok")
	if out != "export TOKEN='z'\n" {
		t.Errorf("export --filter = %q", out)
	}
}

func TestSearchByName(t *testing.T) {
	e := newEnv(t)
	for _, k := range []string{"github_token", "GitLab_Token", "db_pass"} {
		e.mustRun("v", "set", k)
	}
	// Searching by name must not need the private key.
	t.Setenv("AGE_KEY_FILE", "")

	out, _ := e.mustRun("", "search", "TOKEN")
	if out != "GitLab_Token\ngithub_token\n" {
		t.Errorf("search = %q", out)
	}
	out, _ = e.mustRun("", "search", "git*")
	if out != "GitLab_Token\ngithub_token\n" {
		t.Errorf("glob search = %q", out)
	}
	out, _ = e.mustRun("", "search", "git")
	if out != "GitLab_Token\ngithub_token\n" {
		t.Errorf("substring search = %q", out)
	}
	if out, _ = e.mustRun("", "search", "zzz"); out != "" {
		t.Errorf("no-match search = %q", out)
	}
	if _, _, err := e.run("", "search"); err == nil {
		t.Error("search without a pattern succeeded")
	}
	if _, _, err := e.run("", "search", "[bad"); err == nil {
		t.Error("invalid glob accepted")
	}
}

func TestSearchByValue(t *testing.T) {
	e := newEnv(t)
	e.mustRun("alpha-shared-123", "set", "one")
	e.mustRun("beta-shared-456", "set", "two")
	e.mustRun("gamma", "set", "three")

	out, _ := e.mustRun("shared\n", "search", "--value")
	if out != "one: al****23\ntwo: be****56\n" {
		t.Errorf("search --value = %q", out)
	}
	if strings.Contains(out, "shared") {
		t.Error("search --value leaked the full value")
	}

	out, _ = e.mustRun("shared", "search", "--value", "tw")
	if out != "two: be****56\n" {
		t.Errorf("search --value with pattern = %q", out)
	}

	if _, _, err := e.run("", "search", "--value"); err == nil {
		t.Error("empty search text accepted")
	}
	// The text can never be given on the command line.
	if _, _, err := e.run("shared", "search", "--value", "a", "b"); err == nil {
		t.Error("extra argument accepted")
	}
}

func TestEncryptDecryptStdin(t *testing.T) {
	e := newEnv(t)
	plain := "export A=1\nexport B='two words'\n"
	enc, _ := e.mustRun(plain, "encrypt")
	if !strings.HasPrefix(enc, "age-encryption.org/v1\n") {
		t.Fatalf("not an age file: %q", enc[:20])
	}
	dec, _ := e.mustRun(enc, "decrypt")
	if dec != plain {
		t.Errorf("decrypt = %q", dec)
	}
	if _, _, err := e.run("garbage", "decrypt"); err == nil {
		t.Error("decrypt of garbage succeeded")
	}
}

// A store written by v1.11.0 is plain YAML with one "data" map of binary
// age values encrypted for the single own recipient.
func TestReadsLegacyStore(t *testing.T) {
	e := newEnv(t)
	enc, err := encryptValue("legacy", e.id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(e.work, "legacy.yaml")
	e2 := &KeyValue{Data: map[string]string{"old": enc}}
	if err := saveStore(store, e2); err != nil {
		t.Fatal(err)
	}
	if out, _ := e.mustRun("", "get", "old", "-f", store); out != "legacy\n" {
		t.Errorf("get = %q", out)
	}
	raw, _ := os.ReadFile(store)
	if !strings.HasPrefix(string(raw), "data:\n") {
		t.Errorf("store is not the legacy YAML layout: %q", raw[:10])
	}
}

func TestGenerateKeyDoesNotOverwrite(t *testing.T) {
	e := newEnv(t)
	e.mustRun("", "generate-key")
	first, err := os.ReadFile(filepath.Join("keys", "key.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentity(filepath.Join("keys", "key.txt")); err != nil {
		t.Errorf("generated key does not parse: %v", err)
	}
	if _, _, err := e.run("", "generate-key"); err == nil {
		t.Error("generate-key overwrote an existing key")
	}
	second, _ := os.ReadFile(filepath.Join("keys", "key.txt"))
	if !bytes.Equal(first, second) {
		t.Error("existing key was modified")
	}
}

func TestShellrcAndVersion(t *testing.T) {
	e := newEnv(t)
	if out, _ := e.mustRun("", "shellrc"); !strings.Contains(out, "PROMPT_COMMAND") {
		t.Errorf("shellrc = %q", out)
	}
	if out, _ := e.mustRun("", "version"); !strings.HasPrefix(out, "Version: ") {
		t.Errorf("version = %q", out)
	}
}
