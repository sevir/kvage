//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// minMemlock is the smallest RLIMIT_MEMLOCK with which the agent locks its
// memory. mlockall accounts the whole address space of the Go runtime
// (above 1 GiB), and a later allocation that crossed the limit would kill
// the process, so below this the agent runs without locked memory.
const minMemlock = 4 << 30

// hardenProcess makes the agent's memory harder to get at and returns a
// description of what could and could not be done.
func hardenProcess() []string {
	var report []string
	note := func(what string, err error) {
		if err != nil {
			report = append(report, fmt.Sprintf("%s: NOT applied (%v)", what, err))
		} else {
			report = append(report, what+": applied")
		}
	}

	// Not dumpable: no core dumps, and other processes of the same user
	// cannot ptrace the agent or read /proc/<pid>/mem.
	note("no ptrace or memory access by the same user (PR_SET_DUMPABLE=0)",
		unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0))
	note("no core dumps (RLIMIT_CORE=0)",
		unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}))

	var lim unix.Rlimit
	err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim)
	if err == nil && lim.Cur != unix.RLIM_INFINITY && lim.Cur < minMemlock {
		err = fmt.Errorf("RLIMIT_MEMLOCK is %d MiB, at least %d MiB needed", lim.Cur>>20, minMemlock>>20)
	}
	if err == nil {
		err = unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE | unix.MCL_ONFAULT)
	}
	note("memory kept out of swap (mlockall)", err)
	return report
}

// checkPeer accepts only a peer that runs as the same user. With sameExe
// (the agent checking a client) the peer must also be the same kvage
// executable as this process.
//
// The executable check is a hurdle, not a boundary: another program of the
// same user can simply run kvage itself. It keeps arbitrary programs from
// speaking the agent protocol directly. A client cannot apply it to the
// agent, whose /proc entries are closed because it is not dumpable; there
// the private runtime directory and the user check are what is relied on.
func checkPeer(conn *net.UnixConn, sameExe bool) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var credErr error
	pidfd := -1
	err = raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		// Not available before Linux 6.5; used to detect PID reuse.
		if p, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD); err == nil {
			pidfd = p
		}
	})
	if pidfd >= 0 {
		defer unix.Close(pidfd)
	}
	if err != nil {
		return err
	}
	if credErr != nil {
		return credErr
	}
	if int(cred.Uid) != os.Getuid() {
		return errors.New("peer is another user")
	}
	if !sameExe {
		return nil
	}

	self, err := os.Stat("/proc/self/exe")
	if err != nil {
		return err
	}
	peer, err := os.Stat(fmt.Sprintf("/proc/%d/exe", cred.Pid))
	if err != nil {
		return errors.New("cannot identify the peer executable")
	}
	if !os.SameFile(self, peer) {
		return errors.New("peer is not this kvage executable")
	}
	if pidfd >= 0 {
		// The peer must still be the process whose executable was checked.
		fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		if n, err := unix.Poll(fds, 0); err != nil || n != 0 {
			return errors.New("peer exited during the check")
		}
	}
	return nil
}
