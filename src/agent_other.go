//go:build !linux && !darwin

package main

import (
	"errors"
	"io"
	"time"
)

// There is no session agent on this platform: a passphrase-protected key
// asks for its passphrase on every command.

const agentSupported = false

var errAgentDown = errors.New("no session agent is running")

var errNoAgent = errors.New("the session agent is not supported on this platform")

type agentRequest struct {
	Op          string
	KeyID       string
	KeyPath     string
	Identity    string
	Ciphertexts [][]byte
}

type agentKeyInfo struct {
	KeyID     string
	Path      string
	Recipient string
	Since     time.Time
}

type agentResponse struct {
	Error      string
	Locked     bool
	Plaintexts [][]byte
	Errors     []string
	Recipient  string
	Keys       []agentKeyInfo
	PID        int
	Started    time.Time
	Timeout    string
	Hardening  []string
	Version    string
}

func agentCall(*agentRequest) (*agentResponse, error) { return nil, errAgentDown }
func ensureAgent(time.Duration) error                 { return errNoAgent }
func stopAgentByPID() error                           { return errAgentDown }
func runAgent(time.Duration, io.Writer) error         { return errNoAgent }
