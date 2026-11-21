//go:build darwin

package main

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// hardenProcess does what is portable: no core dumps. macOS has no
// equivalent of PR_SET_DUMPABLE for an unsigned binary, and the agent does
// not lock its memory there.
func hardenProcess() []string {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return []string{fmt.Sprintf("no core dumps (RLIMIT_CORE=0): NOT applied (%v)", err)}
	}
	return []string{
		"no core dumps (RLIMIT_CORE=0): applied",
		"memory access by the same user: NOT restricted on this platform",
		"memory kept out of swap: NOT applied on this platform",
	}
}

// checkPeer accepts only a peer running as the same user. The executable
// is not checked on this platform.
func checkPeer(conn *net.UnixConn, sameExe bool) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return err
	}
	if credErr != nil {
		return credErr
	}
	if int(cred.Uid) != os.Getuid() {
		return errors.New("peer is another user")
	}
	return nil
}
