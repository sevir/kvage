//go:build linux || darwin

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The session agent is a background kvage process that keeps unlocked
// identities in memory and performs decryptions on behalf of later kvage
// commands. The identity is handed to it once, on unlock, and never leaves
// it again: clients send ciphertexts and get plaintexts back.
//
// It listens on a unix socket in a private runtime directory and only
// serves peers that pass checkPeer (same user; on Linux also the same
// executable). One request and one response, both JSON, per connection.

const agentSupported = true

const (
	agentSocketName = "agent.sock"
	agentPIDName    = "agent.pid"
	agentMaxRequest = 64 << 20
)

// How long an agent without keys stays around, and how often it checks its
// exit conditions. Variables so tests can shorten them.
var (
	agentEmptyGrace = 30 * time.Second
	agentTick       = time.Second
)

var errAgentDown = errors.New("no session agent is running")

type agentRequest struct {
	Op          string   `json:"op"`
	KeyID       string   `json:"key_id,omitempty"`
	KeyPath     string   `json:"key_path,omitempty"`
	Ciphertexts [][]byte `json:"ciphertexts,omitempty"`
}

type agentKeyInfo struct {
	KeyID     string    `json:"key_id"`
	Path      string    `json:"path"`
	Recipient string    `json:"recipient"`
	Since     time.Time `json:"since"`
	// Protection says where the agent keeps this key.
	Protection string `json:"protection"`
}

type agentResponse struct {
	Error      string         `json:"error,omitempty"`
	Locked     bool           `json:"locked,omitempty"`
	Plaintexts [][]byte       `json:"plaintexts,omitempty"`
	Errors     []string       `json:"errors,omitempty"`
	Recipient  string         `json:"recipient,omitempty"`
	Keys       []agentKeyInfo `json:"keys,omitempty"`
	PID        int            `json:"pid,omitempty"`
	Started    time.Time      `json:"started,omitempty"`
	Timeout    string         `json:"timeout,omitempty"`
	Hardening  []string       `json:"hardening,omitempty"`
	Version    string         `json:"version,omitempty"`
}

// agentRuntimeDir returns the private directory of the agent socket,
// creating it if needed. It must belong to the user and be closed to
// everybody else, otherwise another user could plant a fake agent there.
func agentRuntimeDir() (string, error) {
	var dir string
	if base := os.Getenv("XDG_RUNTIME_DIR"); base != "" {
		dir = filepath.Join(base, "kvage")
	} else {
		dir = filepath.Join(os.TempDir(), fmt.Sprintf("kvage-%d", os.Getuid()))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating runtime directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || int(st.Uid) != os.Getuid() || info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("runtime directory %s is not a private directory of the current user", dir)
	}
	return dir, nil
}

func agentSocketPath() (string, error) {
	dir, err := agentRuntimeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, agentSocketName), nil
}

// ---- client ----

// Every request starts with one byte: frameJSON when a JSON request
// follows, frameKey when the 32 raw bytes of a private key come first (the
// "add" request). The key travels outside the JSON so that the agent can
// read it straight into a buffer it is able to erase.
const (
	frameJSON = 'J'
	frameKey  = 'K'
)

// agentCall sends one request to the running agent.
func agentCall(req *agentRequest) (*agentResponse, error) {
	return agentCallKey(req, nil)
}

// agentAdd hands a private key to the agent.
func agentAdd(keyID, keyPath string, secret *[x25519Size]byte) error {
	_, err := agentCallKey(&agentRequest{Op: "add", KeyID: keyID, KeyPath: keyPath}, secret)
	return err
}

func agentCallKey(req *agentRequest, secret *[x25519Size]byte) (*agentResponse, error) {
	sock, err := agentSocketPath()
	if err != nil {
		return nil, err
	}
	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return nil, errAgentDown
	}
	conn := c.(*net.UnixConn)
	defer conn.Close()
	// The identity is sent to the agent on unlock: make sure the process
	// listening there is ours.
	if err := checkPeer(conn, false); err != nil {
		return nil, fmt.Errorf("refusing to talk to the process on %s: %w", sock, err)
	}
	conn.SetDeadline(time.Now().Add(2 * time.Minute))
	var werr error
	if secret != nil {
		_, werr = conn.Write([]byte{frameKey})
		if werr == nil {
			_, werr = conn.Write(secret[:])
		}
	} else {
		_, werr = conn.Write([]byte{frameJSON})
	}
	if werr == nil {
		werr = json.NewEncoder(conn).Encode(req)
	}
	if werr != nil {
		return nil, fmt.Errorf("talking to the session agent: %w", werr)
	}
	conn.CloseWrite()
	var resp agentResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("talking to the session agent: %w", err)
	}
	if resp.Error != "" {
		return &resp, errors.New(resp.Error)
	}
	return &resp, nil
}

// agentCommand builds the command line of the agent process. A variable so
// tests can re-execute the test binary instead.
var agentCommand = func(self string, timeout time.Duration, tpmMode string) *exec.Cmd {
	return exec.Command(self, "agent", "--timeout", timeout.String(), "--tpm", tpmMode)
}

// spawnAgent starts the background agent. A variable so tests can run the
// agent in-process.
var spawnAgent = func(timeout time.Duration, tpmMode string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	ready, w, err := os.Pipe()
	if err != nil {
		return err
	}
	defer ready.Close()

	cmd := agentCommand(self, timeout, tpmMode)
	cmd.Dir = "/"
	cmd.Stdout = w
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// A minimal environment: nothing of the caller's shell leaks into the
	// long-lived process.
	for _, k := range []string{"XDG_RUNTIME_DIR", "HOME", "TMPDIR"} {
		if v, ok := os.LookupEnv(k); ok {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	err = cmd.Start()
	w.Close()
	if err != nil {
		return err
	}
	cmd.Process.Release()

	// The agent writes one line once it is listening (or has found that
	// another agent already is).
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := ready.Read(buf)
		if strings.HasPrefix(string(buf[:n]), "ready") {
			done <- nil
		} else {
			done <- errors.New("the session agent did not start")
		}
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		return errors.New("timed out waiting for the session agent")
	}
}

// ensureAgent makes sure an agent is running.
func ensureAgent(timeout time.Duration, tpmMode string) error {
	if _, err := agentCall(&agentRequest{Op: "status"}); err == nil {
		return nil
	} else if !errors.Is(err, errAgentDown) {
		return err
	}
	if err := spawnAgent(timeout, tpmMode); err != nil {
		return err
	}
	_, err := agentCall(&agentRequest{Op: "status"})
	return err
}

// stopAgentByPID is the fallback for "lock" when the agent will not talk to
// this binary (for instance after kvage was upgraded): it asks the recorded
// process to terminate, which makes it drop every key.
func stopAgentByPID() error {
	dir, err := agentRuntimeDir()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(dir, agentPIDName))
	if err != nil {
		return errAgentDown
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return errAgentDown
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return errAgentDown
	}
	return nil
}

// ---- server ----

type agentKey struct {
	slot   keySlot
	public [x25519Size]byte
	info   agentKeyInfo
}

type agentServer struct {
	mu        sync.Mutex
	keys      map[string]*agentKey
	started   time.Time
	lastUse   time.Time
	emptyAt   time.Time
	timeout   time.Duration
	tpmMode   string
	hardening []string
	stop      chan struct{}
	stopOnce  sync.Once
}

func newAgentServer(timeout time.Duration, tpmMode string, hardening []string) *agentServer {
	now := time.Now()
	return &agentServer{
		keys:      make(map[string]*agentKey),
		started:   now,
		lastUse:   now,
		emptyAt:   now,
		timeout:   timeout,
		tpmMode:   tpmMode,
		hardening: hardening,
		stop:      make(chan struct{}),
	}
}

func (s *agentServer) shutdown() {
	s.stopOnce.Do(func() { close(s.stop) })
}

// dropAll erases every key. The caller holds s.mu.
func (s *agentServer) dropAll() {
	for id, k := range s.keys {
		k.slot.close()
		delete(s.keys, id)
	}
}

// handle serves one request. secret is the key that came with an "add"
// request, nil otherwise; it is erased by the caller.
func (s *agentServer) handle(req *agentRequest, secret *[x25519Size]byte) *agentResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Looking at the session is not using it: "status" must not keep an
	// idle session alive.
	if req.Op != "status" {
		s.lastUse = time.Now()
	}

	switch req.Op {
	case "status":
		resp := &agentResponse{
			PID:       os.Getpid(),
			Started:   s.started,
			Hardening: s.hardening,
			Version:   Version,
		}
		if s.timeout > 0 {
			resp.Timeout = s.timeout.String()
		}
		for _, k := range s.keys {
			resp.Keys = append(resp.Keys, k.info)
		}
		return resp

	case "add":
		if secret == nil || req.KeyID == "" {
			return &agentResponse{Error: "invalid identity"}
		}
		slot, err := newKeySlot(secret, s.tpmMode)
		if err != nil {
			return &agentResponse{Error: err.Error()}
		}
		if old, ok := s.keys[req.KeyID]; ok {
			old.slot.close()
		}
		public := publicFromSecret(secret)
		s.keys[req.KeyID] = &agentKey{
			slot:   slot,
			public: public,
			info: agentKeyInfo{
				KeyID:      req.KeyID,
				Path:       req.KeyPath,
				Recipient:  recipientKeyString(public),
				Since:      time.Now(),
				Protection: slot.describe(),
			},
		}
		return &agentResponse{Recipient: recipientKeyString(public)}

	case "recipient":
		k, ok := s.keys[req.KeyID]
		if !ok {
			return &agentResponse{Locked: true}
		}
		return &agentResponse{Recipient: k.info.Recipient}

	case "decrypt":
		k, ok := s.keys[req.KeyID]
		if !ok {
			return &agentResponse{Locked: true}
		}
		resp := &agentResponse{
			Plaintexts: make([][]byte, len(req.Ciphertexts)),
			Errors:     make([]string, len(req.Ciphertexts)),
		}
		err := k.slot.use(func(secret *[x25519Size]byte) error {
			identity := newSecretIdentity(secret, k.public)
			for i, c := range req.Ciphertexts {
				plain, err := decryptValue(string(c), identity)
				if err != nil {
					resp.Errors[i] = err.Error()
					continue
				}
				resp.Plaintexts[i] = []byte(plain)
			}
			return nil
		})
		if err != nil {
			// The key could not be produced (for instance the TPM object
			// did not survive a hibernation): the session is over.
			k.slot.close()
			delete(s.keys, req.KeyID)
			return &agentResponse{Error: fmt.Sprintf("the session was lost (%v): run `kvage unlock`", err)}
		}
		return resp

	case "lock":
		if req.KeyID == "" {
			s.dropAll()
		} else if k, ok := s.keys[req.KeyID]; ok {
			k.slot.close()
			delete(s.keys, req.KeyID)
		}
		if len(s.keys) == 0 {
			// Nothing left to protect: exit, which is the only reliable
			// way to get rid of every copy of the keys in this process.
			s.shutdown()
		}
		return &agentResponse{}
	}
	return &agentResponse{Error: "unknown request"}
}

func (s *agentServer) serveConn(conn *net.UnixConn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Minute))
	enc := json.NewEncoder(conn)
	if err := checkPeer(conn, true); err != nil {
		enc.Encode(&agentResponse{Error: "request refused: " + err.Error()})
		return
	}
	var frame [1]byte
	if _, err := io.ReadFull(conn, frame[:]); err != nil {
		return
	}
	var secret *[x25519Size]byte
	switch frame[0] {
	case frameJSON:
	case frameKey:
		secret = new([x25519Size]byte)
		defer wipe(secret[:])
		if _, err := io.ReadFull(conn, secret[:]); err != nil {
			return
		}
	default:
		enc.Encode(&agentResponse{Error: "malformed request"})
		return
	}
	var req agentRequest
	if err := json.NewDecoder(io.LimitReader(conn, agentMaxRequest)).Decode(&req); err != nil {
		enc.Encode(&agentResponse{Error: "malformed request"})
		return
	}
	enc.Encode(s.handle(&req, secret))
}

// expired reports whether the agent should stop: nothing to hold, idle for
// longer than the configured timeout, or its socket is gone (the runtime
// directory is removed when the user session ends).
func (s *agentServer) expired(sock string, own os.FileInfo) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if len(s.keys) == 0 {
		if now.Sub(s.emptyAt) > agentEmptyGrace {
			return true
		}
	} else {
		s.emptyAt = now
	}
	if s.timeout > 0 && now.Sub(s.lastUse) > s.timeout {
		return true
	}
	current, err := os.Lstat(sock)
	return err != nil || !os.SameFile(own, current)
}

// serve runs until the agent is locked, expires or is told to stop.
func (s *agentServer) serve(l *net.UnixListener, sock string) {
	own, _ := os.Lstat(sock)
	go func() {
		for {
			conn, err := l.AcceptUnix()
			if err != nil {
				return
			}
			go s.serveConn(conn)
		}
	}()

	ticker := time.NewTicker(agentTick)
	defer ticker.Stop()
loop:
	for {
		select {
		case <-s.stop:
			break loop
		case <-ticker.C:
			if own == nil || s.expired(sock, own) {
				break loop
			}
		}
	}

	l.SetUnlinkOnClose(false)
	l.Close()
	s.mu.Lock()
	s.dropAll()
	s.mu.Unlock()
	if current, err := os.Lstat(sock); err == nil && own != nil && os.SameFile(own, current) {
		os.Remove(sock)
	}
}

// listenAgent binds the agent socket. It returns nil without error when
// another agent is already serving it.
func listenAgent() (*net.UnixListener, string, error) {
	sock, err := agentSocketPath()
	if err != nil {
		return nil, "", err
	}
	if c, err := net.DialTimeout("unix", sock, time.Second); err == nil {
		c.Close()
		return nil, sock, nil
	}
	os.Remove(sock) // stale socket of a dead agent

	old := syscall.Umask(0o077)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, "", fmt.Errorf("listening on %s: %w", sock, err)
	}
	return l, sock, nil
}

// runAgent is the body of the hidden "kvage agent" command.
func runAgent(timeout time.Duration, tpmMode string, ready io.Writer) error {
	hardening := hardenProcess()
	l, sock, err := listenAgent()
	if err != nil {
		return err
	}
	if l == nil {
		fmt.Fprintln(ready, "ready (already running)")
		return nil
	}
	pidFile := filepath.Join(filepath.Dir(sock), agentPIDName)
	os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
	defer os.Remove(pidFile)

	s := newAgentServer(timeout, tpmMode, hardening)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	signal.Ignore(syscall.SIGHUP)
	go func() {
		<-sig
		s.shutdown()
	}()

	fmt.Fprintln(ready, "ready")
	if f, ok := ready.(*os.File); ok {
		f.Close()
	}
	s.serve(l, sock)
	return nil
}
