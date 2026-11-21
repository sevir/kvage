//go:build linux || darwin

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

func init() {
	scryptWorkFactor = 8        // keep the tests fast
	defaultTPMMode = tpmModeOff // TPM tests ask for it explicitly
}

const testAgentEnv = "KVAGE_TEST_RUN_AGENT"

// TestMain lets the test binary act as the real, separate, hardened agent
// process: started with testAgentEnv set, it runs the agent and exits.
func TestMain(m *testing.M) {
	if os.Getenv(testAgentEnv) != "" {
		if err := runAgent(0, os.Getenv(testAgentEnv), os.Stdout); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// useRealAgent gives the test a private runtime directory and starts the
// agent as its own process (this test binary re-executed), the way kvage
// starts it.
func useRealAgent(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("", "kvg")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", dir)
	t.Setenv(testAgentEnv, "1")
	old := agentCommand
	agentCommand = func(self string, timeout time.Duration, tpmMode string) *exec.Cmd {
		cmd := exec.Command(self, "-test.run=^$")
		cmd.Env = []string{testAgentEnv + "=" + tpmMode}
		return cmd
	}
	t.Cleanup(func() {
		agentCommand = old
		stopAgentByPID()
		waitFor(t, "the agent process to exit", func() bool { return !agentRunning() })
		os.RemoveAll(dir)
	})
}

// processGone reports whether pid has exited. The test process is the
// agent's parent and never reaps it, so a zombie counts as gone.
func processGone(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return true
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return runtime.GOOS == "linux"
	}
	i := strings.LastIndexByte(string(stat), ')')
	return i >= 0 && strings.HasPrefix(string(stat[i+1:]), " Z")
}

func agentPID(t *testing.T) int {
	t.Helper()
	resp, err := agentCall(&agentRequest{Op: "status"})
	if err != nil {
		t.Fatalf("agent status: %v", err)
	}
	return resp.PID
}

// The agent as a separate process: started on first use, hardened, serving
// this executable, gone after lock.
func TestAgentProcess(t *testing.T) {
	e := newEnv(t)
	useRealAgent(t)
	e.mustRun("v", "set", "k")
	e.protect("pw")

	p := usePrompts(t, "pw")
	if out, errw := e.mustRun("", "get", "k"); out != "v\n" || errw != "" {
		t.Fatalf("get: out=%q stderr=%q", out, errw)
	}
	e.mustRun("", "get", "k")
	if p.asked != 1 {
		t.Errorf("asked %d times, want 1", p.asked)
	}

	pid := agentPID(t)
	if pid == os.Getpid() || pid == 0 {
		t.Fatalf("agent pid = %d: not a separate process", pid)
	}
	if runtime.GOOS == "linux" {
		// Not dumpable: its /proc entries are closed to the same user,
		// which is what blocks ptrace and /proc/<pid>/mem.
		for _, f := range []string{"mem", "environ"} {
			if fh, err := os.Open(fmt.Sprintf("/proc/%d/%s", pid, f)); err == nil {
				fh.Close()
				t.Errorf("/proc/%d/%s is readable", pid, f)
			}
		}
		out, _ := e.mustRun("", "status")
		if !strings.Contains(out, "PR_SET_DUMPABLE=0): applied") || !strings.Contains(out, "RLIMIT_CORE=0): applied") {
			t.Errorf("hardening not reported:\n%s", out)
		}
	}
	sock, _ := agentSocketPath()
	if m := statMode(t, sock); m&0o077 != 0 {
		t.Errorf("socket mode = %o", m)
	}

	e.mustRun("", "lock")
	waitFor(t, "the agent process to exit", func() bool { return processGone(pid) })
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Error("socket left behind after lock")
	}
}

// When the agent refuses this binary, lock still works through the PID file.
func TestLockByPID(t *testing.T) {
	e := newEnv(t)
	useRealAgent(t)
	e.protect("pw")
	usePrompts(t, "pw")
	e.mustRun("", "unlock")
	pid := agentPID(t)
	if err := stopAgentByPID(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the agent process to exit", func() bool { return processGone(pid) })
}

// prompts replaces the terminal: it answers passphrase requests from a
// queue and counts them.
type prompts struct {
	t       *testing.T
	answers []string
	asked   int
}

func usePrompts(t *testing.T, answers ...string) *prompts {
	t.Helper()
	p := &prompts{t: t, answers: answers}
	old := readPassphrase
	readPassphrase = func(string) ([]byte, error) {
		p.asked++
		if len(p.answers) == 0 {
			return nil, errors.New("unexpected passphrase prompt")
		}
		answer := p.answers[0]
		p.answers = p.answers[1:]
		return []byte(answer), nil
	}
	t.Cleanup(func() { readPassphrase = old })
	return p
}

// useAgent gives the test a private runtime directory and runs the session
// agent inside the test process instead of forking kvage.
func useAgent(t *testing.T) {
	t.Helper()
	dir, err := os.MkdirTemp("", "kvg")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", dir)

	oldSpawn, oldTick, oldGrace := spawnAgent, agentTick, agentEmptyGrace
	agentTick = 20 * time.Millisecond
	var servers []*agentServer
	var done []chan struct{}
	spawnAgent = func(timeout time.Duration, tpmMode string) error {
		l, sock, err := listenAgent()
		if err != nil || l == nil {
			return err
		}
		s := newAgentServer(timeout, tpmMode, []string{"in-process test agent"})
		ch := make(chan struct{})
		servers, done = append(servers, s), append(done, ch)
		go func() {
			s.serve(l, sock)
			close(ch)
		}()
		return nil
	}
	t.Cleanup(func() {
		for i, s := range servers {
			s.shutdown()
			<-done[i]
		}
		spawnAgent, agentTick, agentEmptyGrace = oldSpawn, oldTick, oldGrace
		os.RemoveAll(dir)
	})
}

func agentRunning() bool {
	_, err := agentCall(&agentRequest{Op: "status"})
	return err == nil
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// protect turns the environment's plain key into a passphrase-protected one.
func (e *env) protect(passphrase string) {
	e.t.Helper()
	p := usePrompts(e.t, passphrase, passphrase)
	e.mustRun("", "vault", "init")
	if p.asked != 2 {
		e.t.Fatalf("vault init asked %d times", p.asked)
	}
}

func TestVaultInitProtectsExistingKey(t *testing.T) {
	e := newEnv(t)
	useAgent(t)
	e.mustRun("before", "set", "k")
	e.protect("correct horse")

	data, _ := os.ReadFile(e.keyPath)
	if !bytes.HasPrefix(data, []byte(armor.Header)) || bytes.Contains(data, []byte("AGE-SECRET-KEY")) {
		t.Fatalf("key file is not protected:\n%s", data)
	}
	if runtime.GOOS != "windows" {
		if m := statMode(t, e.keyPath); m != 0o600 {
			t.Errorf("key file mode = %o", m)
		}
	}
	pub, _ := os.ReadFile(e.keyPath + ".pub")
	if strings.TrimSpace(string(pub)) != e.id.Recipient().String() {
		t.Errorf("public key file = %q", pub)
	}

	// Standard age format: the age library opens it with the passphrase and
	// finds the very same identity, so nothing needs re-encrypting.
	scrypt, _ := age.NewScryptIdentity("correct horse")
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(data)), scrypt)
	if err != nil {
		t.Fatalf("age cannot open the key file: %v", err)
	}
	ids, err := age.ParseIdentities(r)
	if err != nil || len(ids) != 1 || ids[0].(*age.X25519Identity).String() != e.id.String() {
		t.Errorf("identity changed: %v", err)
	}

	p := usePrompts(t, "correct horse")
	if out, _ := e.mustRun("", "get", "k"); out != "before\n" {
		t.Errorf("get = %q", out)
	}
	// The session is open now: no more prompts.
	e.mustRun("", "get", "k")
	e.mustRun("", "list")
	if p.asked != 1 {
		t.Errorf("asked %d times, want 1", p.asked)
	}

	if _, _, err := e.run("", "vault", "init"); err == nil {
		t.Error("vault init on a protected key succeeded")
	}
}

func TestVaultInitCreatesKey(t *testing.T) {
	e := newEnv(t)
	useAgent(t)
	t.Setenv("AGE_KEY_FILE", "")
	usePrompts(t, "pw", "pw", "pw")
	e.mustRun("", "vault", "init")
	path := filepath.Join(getConfigPath(), keyFileName)
	if data, err := os.ReadFile(path); err != nil || !isEncryptedKey(data) {
		t.Fatalf("no protected key in the config directory: %v", err)
	}
	e.mustRun("v", "set", "k")
	if out, _ := e.mustRun("", "get", "k"); out != "v\n" {
		t.Errorf("get = %q", out)
	}
}

func TestVaultInitRejectsMismatchAndEmpty(t *testing.T) {
	e := newEnv(t)
	before, _ := os.ReadFile(e.keyPath)
	usePrompts(t, "one", "two")
	if _, _, err := e.run("", "vault", "init"); err == nil {
		t.Error("mismatched passphrases accepted")
	}
	usePrompts(t, "")
	if _, _, err := e.run("", "vault", "init"); err == nil {
		t.Error("empty passphrase accepted")
	}
	after, _ := os.ReadFile(e.keyPath)
	if !bytes.Equal(before, after) {
		t.Error("key file changed after a failed vault init")
	}
}

func TestWrongPassphrase(t *testing.T) {
	e := newEnv(t)
	useAgent(t)
	e.mustRun("v", "set", "k")
	e.protect("right")
	usePrompts(t, "wrong")
	_, _, err := e.run("", "get", "k")
	if err == nil || !strings.Contains(err.Error(), "incorrect passphrase") {
		t.Errorf("err = %v", err)
	}
	if agentRunning() {
		t.Error("an agent was started with a wrong passphrase")
	}
}

func TestLockEndsTheSession(t *testing.T) {
	e := newEnv(t)
	useAgent(t)
	e.mustRun("v", "set", "k")
	e.protect("pw")

	p := usePrompts(t, "pw", "pw")
	_, errw := e.mustRun("", "unlock")
	if !strings.Contains(errw, "Unlocked") {
		t.Errorf("unlock: %q", errw)
	}
	e.mustRun("", "get", "k")
	if p.asked != 1 {
		t.Fatalf("asked %d times", p.asked)
	}
	if _, errw := e.mustRun("", "unlock"); !strings.Contains(errw, "Already unlocked") {
		t.Errorf("second unlock: %q", errw)
	}

	e.mustRun("", "lock")
	waitFor(t, "the agent to stop", func() bool { return !agentRunning() })
	if _, errw := e.mustRun("", "lock"); !strings.Contains(errw, "Already locked") {
		t.Errorf("second lock: %q", errw)
	}

	e.mustRun("", "get", "k")
	if p.asked != 2 {
		t.Errorf("no prompt after lock (asked %d)", p.asked)
	}
}

func TestSessionModeAlways(t *testing.T) {
	e := newEnv(t)
	useAgent(t)
	e.mustRun("v", "set", "k")
	e.protect("pw")
	writeFile(t, userConfigPath(), "session:\n  mode: always\n")

	p := usePrompts(t, "pw", "pw")
	e.mustRun("", "get", "k")
	e.mustRun("", "get", "k")
	if p.asked != 2 {
		t.Errorf("asked %d times, want 2", p.asked)
	}
	if agentRunning() {
		t.Error("an agent runs in mode always")
	}
	if _, _, err := e.run("", "unlock"); err == nil {
		t.Error("unlock succeeded in mode always")
	}
}

func TestSessionTimeout(t *testing.T) {
	e := newEnv(t)
	useAgent(t)
	e.mustRun("v", "set", "k")
	e.protect("pw")
	writeFile(t, userConfigPath(), "session:\n  timeout: 150ms\n")

	p := usePrompts(t, "pw", "pw")
	e.mustRun("", "get", "k")
	waitFor(t, "the idle timeout", func() bool { return !agentRunning() })
	e.mustRun("", "get", "k")
	if p.asked != 2 {
		t.Errorf("asked %d times, want 2", p.asked)
	}
}

func TestInvalidConfigIsReported(t *testing.T) {
	e := newEnv(t)
	e.mustRun("v", "set", "k")
	for _, cfg := range []string{"session:\n  mode: sometimes\n", "session:\n  timeout: soon\n", "session: [\n"} {
		writeFile(t, userConfigPath(), cfg)
		if _, _, err := e.run("", "get", "k"); err == nil {
			t.Errorf("config %q accepted", cfg)
		}
	}
}

func TestAgentStopsWhenItsSocketDisappears(t *testing.T) {
	e := newEnv(t)
	useAgent(t)
	e.mustRun("v", "set", "k")
	e.protect("pw")
	usePrompts(t, "pw")
	e.mustRun("", "unlock")

	sock, _ := agentSocketPath()
	resp, err := agentCall(&agentRequest{Op: "status"})
	if err != nil || len(resp.Keys) != 1 {
		t.Fatalf("status: %+v, %v", resp, err)
	}
	// What happens at logout: the runtime directory goes away.
	os.Remove(sock)
	waitFor(t, "the agent to notice", func() bool {
		_, err := os.Stat(sock)
		return os.IsNotExist(err) && !agentRunning()
	})
}

func TestHookDoesNotPromptWhenLocked(t *testing.T) {
	e := newEnv(t)
	useAgent(t)
	e.writeRC("export A=1\n")
	e.protect("pw")

	p := usePrompts(t)
	out, errw, err := e.run("", "rc", "--no-prompt")
	if err != nil || out != "" {
		t.Errorf("out=%q err=%v", out, err)
	}
	if strings.Count(errw, "\n") != 1 || !strings.Contains(errw, "locked") {
		t.Errorf("want a one-line notice, got %q", errw)
	}
	if p.asked != 0 {
		t.Error("the hook asked for the passphrase")
	}

	usePrompts(t, "pw")
	e.mustRun("", "unlock")
	usePrompts(t)
	if out, _ := e.mustRun("", "rc", "--no-prompt"); out != "export A='1'\n" {
		t.Errorf("rc after unlock = %q", out)
	}
}

func TestSetDoesNotNeedThePassphrase(t *testing.T) {
	e := newEnv(t)
	useAgent(t)
	e.protect("pw")

	p := usePrompts(t)
	e.mustRun("v", "set", "k")
	if p.asked != 0 {
		t.Error("set asked for the passphrase although the public key is known")
	}
	if !canDecrypt(storeValue(t, e.storeFile(), "k"), e.id) {
		t.Error("value not encrypted for the own key")
	}

	// Without the .pub file the key has to be opened to learn it.
	os.Remove(e.keyPath + ".pub")
	p = usePrompts(t, "pw")
	e.mustRun("v2", "set", "k2")
	if p.asked != 1 {
		t.Errorf("asked %d times, want 1", p.asked)
	}
}

func TestStdinCommandsWithProtectedKey(t *testing.T) {
	e := newEnv(t)
	useAgent(t)
	e.protect("pw")
	usePrompts(t, "pw")

	// The data comes on stdin; the passphrase does not.
	enc, _ := e.mustRun("payload\n", "encrypt")
	if dec, _ := e.mustRun(enc, "decrypt"); dec != "payload\n" {
		t.Errorf("decrypt = %q", dec)
	}
}

func TestRekeyThroughTheAgent(t *testing.T) {
	e := newEnv(t)
	useAgent(t)
	bob := newIdentity(t)
	e.mustRun("one", "set", "a")
	e.protect("pw")
	writeFile(t, filepath.Join(getConfigPath(), recipientsFileName), e.id.Recipient().String()+"\n"+bob.Recipient().String()+"\n")
	usePrompts(t, "pw")
	e.mustRun("", "rekey")
	if got, err := decryptValue(storeValue(t, e.storeFile(), "a"), bob); err != nil || got != "one" {
		t.Errorf("after rekey: %q, %v", got, err)
	}
}

func TestVaultPasswd(t *testing.T) {
	e := newEnv(t)
	useAgent(t)
	e.mustRun("v", "set", "k")
	e.protect("old")
	usePrompts(t, "old")
	e.mustRun("", "unlock")

	usePrompts(t, "old", "new", "new")
	e.mustRun("", "vault", "passwd")

	// The session was for the old file: it is gone, and only the new
	// passphrase opens the key.
	usePrompts(t, "old")
	if _, _, err := e.run("", "get", "k"); err == nil {
		t.Error("old passphrase still works")
	}
	usePrompts(t, "new")
	if out, _ := e.mustRun("", "get", "k"); out != "v\n" {
		t.Errorf("get = %q", out)
	}
}

func TestStatus(t *testing.T) {
	e := newEnv(t)
	useAgent(t)
	out, _ := e.mustRun("", "status")
	for _, want := range []string{e.keyPath, "AGE_KEY_FILE", "plain file", "own key only", "not created yet"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}

	e.protect("pw")
	if out, _ = e.mustRun("", "status"); !strings.Contains(out, "passphrase") || !strings.Contains(out, "Session:     locked") {
		t.Errorf("status:\n%s", out)
	}
	usePrompts(t, "pw")
	e.mustRun("", "unlock")
	if out, _ = e.mustRun("", "status"); !strings.Contains(out, "unlocked since") || !strings.Contains(out, "in-process test agent") {
		t.Errorf("status:\n%s", out)
	}
	// status never asks for anything.
	usePrompts(t)
	e.mustRun("", "lock")
	e.mustRun("", "status")
}

func TestPlainKeyNeedsNoAgent(t *testing.T) {
	e := newEnv(t)
	useAgent(t)
	p := usePrompts(t)
	e.mustRun("v", "set", "k")
	e.mustRun("", "get", "k")
	if p.asked != 0 || agentRunning() {
		t.Error("a plain key file involved a prompt or the agent")
	}
	if _, _, err := e.run("", "unlock"); err == nil {
		t.Error("unlock of a plain key succeeded")
	}
}

// Any program other than this kvage executable is turned away, even when
// it runs as the same user and speaks the protocol.
func TestAgentRefusesOtherExecutables(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the executable check is Linux-only")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	e := newEnv(t)
	useAgent(t)
	e.mustRun("topsecret", "set", "k")
	e.protect("pw")
	usePrompts(t, "pw")
	e.mustRun("", "unlock")

	sock, _ := agentSocketPath()
	script := `import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(b'{"op":"status"}\n')
s.shutdown(socket.SHUT_WR)
sys.stdout.write(s.recv(65536).decode())`
	out, err := exec.Command(python, "-c", script, sock).CombinedOutput()
	if err != nil {
		t.Fatalf("python: %v: %s", err, out)
	}
	if !strings.Contains(string(out), "request refused") || strings.Contains(string(out), "keys") {
		t.Errorf("agent answered a foreign executable: %s", out)
	}
}

func TestRuntimeDirectoryMustBePrivate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)
	if err := os.Mkdir(filepath.Join(dir, "kvage"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := agentRuntimeDir(); err == nil {
		t.Error("a world-readable runtime directory was accepted")
	}
}

func TestSessionTPMRequireFailsWithoutTPM(t *testing.T) {
	if f, err := os.OpenFile("/dev/tpmrm0", os.O_RDWR, 0); err == nil {
		f.Close()
		t.Skip("this machine has a usable TPM")
	}
	e := newEnv(t)
	useAgent(t)
	e.mustRun("v", "set", "k")
	e.protect("pw")
	writeFile(t, userConfigPath(), "session:\n  tpm: require\n")
	usePrompts(t, "pw")
	if _, _, err := e.run("", "unlock"); err == nil || !strings.Contains(err.Error(), "require") {
		t.Errorf("err = %v", err)
	}
}

// Without a usable TPM, "auto" keeps the key in memory and says so.
func TestSessionTPMAutoFallsBack(t *testing.T) {
	if f, err := os.OpenFile("/dev/tpmrm0", os.O_RDWR, 0); err == nil {
		f.Close()
		t.Skip("this machine has a usable TPM")
	}
	e := newEnv(t)
	useAgent(t)
	e.mustRun("v", "set", "k")
	e.protect("pw")
	writeFile(t, userConfigPath(), "session:\n  tpm: auto\n")
	usePrompts(t, "pw")
	if out, _ := e.mustRun("", "get", "k"); out != "v\n" {
		t.Fatalf("get = %q", out)
	}
	if out, _ := e.mustRun("", "status"); !strings.Contains(out, "TPM not used") {
		t.Errorf("status:\n%s", out)
	}
}

func TestInvalidTPMMode(t *testing.T) {
	e := newEnv(t)
	e.mustRun("v", "set", "k")
	writeFile(t, userConfigPath(), "session:\n  tpm: maybe\n")
	if _, _, err := e.run("", "get", "k"); err == nil {
		t.Error("invalid session.tpm accepted")
	}
}
