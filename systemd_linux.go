// +build linux

/*
Copyright 2017, Trusted Key
This file is part of Trusted Key SSH-Agent.

Trusted Key SSH-Agent is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Trusted Key SSH-Agent is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Trusted Key SSH-Agent.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"net"
	"os"
	"strconv"
	"syscall"
	"errors"
)

// fnctl syscall wrapper
func fcntl(fd int, cmd int, arg int) (int, int) {
	r0, _, e1 := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(cmd), uintptr(arg))
	return int(r0), int(e1)
}

// ListenSystemdFds - Listen to FDs provided by systemd
func ListenSystemdFds() ([]net.Listener, error) {
	const listenFdsStart = 3

	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() {
		if err == nil {
			return nil, err
		} else if pid != os.Getpid() {
			return nil, errors.New("Systemd pid mismatch")
		}
	}

	nfds, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || nfds == 0 {
		if err == nil {
			return nil, err
		} else if nfds == 0 {
			return nil, errors.New("nfds is zero (could not listen to any provided fds)")
		}
	}

	listeners := []net.Listener(nil)
	for fd := listenFdsStart; fd < listenFdsStart+nfds; fd++ {
		flags, errno := fcntl(fd, syscall.F_GETFD, 0)
		if errno != 0 {
			if errno != 0 {
				return nil, syscall.Errno(errno)
			}
		}
		if flags&syscall.FD_CLOEXEC != 0 {
			continue
		}
		syscall.CloseOnExec(fd)

		file := os.NewFile(uintptr(fd), "")
		listener, err := net.FileListener(file)
		if err != nil {
			return nil, err
		}
		
		listeners = append(listeners, listener)
	}

	return listeners, nil
}
