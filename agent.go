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
	"fmt"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

// AgentMain - run agent main loop
func AgentMain(quiet bool, outputShell string, configPath string, sockPath string, backendAgent string, systemd bool) {
	stderr := log.New(os.Stderr, "", 0)

	if !quiet && !systemd {
		messageString := "Run this in the terminal where you want to use the agent"
		configString := "or put it into %s"

		switch {
		case outputShell == "bash":
			configString = fmt.Sprintf(configString, "~/.profile")
			fmt.Println(fmt.Sprintf("%s (%s)\nexport SSH_AUTH_SOCK='%s'", messageString, configString, sockPath))
		case outputShell == "fish":
			configString = fmt.Sprintf(configString, "~/.config/fish/config.fish")
			fmt.Println(fmt.Sprintf("%s (%s)\nset -gx SSH_AUTH_SOCK '%s'", messageString, configString, sockPath))
		}
	}

	identities, err := ReadConfig(configPath)
	if err != nil {
		stderr.Println(fmt.Sprintf("Missing configuration in '%s'", configPath))
		os.Exit(1)
	}

	var listeners []net.Listener

	if systemd {
		if os.Getenv("LISTEN_PID") == "" || os.Getenv("LISTEN_FDS") == "" {
			panic("Missing required env vars")
		}

		listeners, err = ListenSystemdFds()
		if err != nil {
			panic(err)
		}

	} else {
		listener, err := net.Listen("unix", sockPath)
		if err != nil {
			panic(fmt.Sprintf("Listen error: %s", err))
		}
		listeners = append(listeners, listener)

		cleanup := func() {
			err := listener.Close()
			if err != nil {
				stderr.Println("Could not close socket file")
			}
		}

		// Do cleanup regardless of how we exited
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		signal.Notify(c, syscall.SIGHUP)
		signal.Notify(c, syscall.SIGTERM)
		go func() {
			for range c {
				cleanup()
				os.Exit(0)
			}
		}()
		defer cleanup()

	}

	// Proxy unknown identities to other agent
	var agentBackend agent.Agent
	if backendAgent != "" {
		agentBackend, err = NewBackendAgent(backendAgent)
	} else {
		// Run in-memory keyring by default
		agentBackend = agent.NewKeyring()
	}
	if err != nil {
		panic(err)
	}

	keyring, err := NewProxyAgent(identities, agentBackend)
	if err != nil {
		panic(err)
	}

	agentConns := make(chan net.Conn)
	for _, listener := range listeners {
		go func(l net.Listener) {
			for {
				c, err := l.Accept()
				if err != nil {
					stderr.Print(err)
					// handle error (and then for example indicate acceptor is down)
					agentConns <- nil
					return
				}
				agentConns <- c
			}
		}(listener)
	}

	for {
		select {
		case c := <-agentConns:
			if c != nil {
				go func() {
					err := agent.ServeAgent(keyring, c)
					if err != nil && err != io.EOF {
						stderr.Print(err)
					}
				}()
			}
		}
	}

}
