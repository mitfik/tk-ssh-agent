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
func AgentMain(quiet bool, outputShell string, configPath string, sockPath string, backendAgent string) {
	stderr := log.New(os.Stderr, "", 0)

	if !quiet {
		switch {
		case outputShell == "bash":
			fmt.Println(fmt.Sprintf("export SSH_AUTH_SOCK='%s'", sockPath))
		case outputShell == "fish":
			fmt.Println(fmt.Sprintf("setenv SSH_AUTH_SOCK '%s'", sockPath))
		}
	}

	identities, err := ReadConfig(configPath)
	if err != nil {
		stderr.Println(fmt.Sprintf("Missing configuration in '%s'", configPath))
		os.Exit(1)
	}

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		panic(fmt.Sprintf("Listen error: %s", err))
	}

	cleanup := func() {
		err := listener.Close()
		if err != nil {
			stderr.Println("Could not close socket file")
		}
	}

	// Do cleanup regardless of how we exited
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)
	go func() {
		for _ = range c {
			cleanup()
			os.Exit(0)
		}
	}()
	defer cleanup()

	var keyring agent.Agent
	if backendAgent != "" {
		keyring, err = NewProxyAgent(identities, backendAgent)
		if err != nil {
			panic(err)
		}
	} else {
		keyring = NewTKeyring(identities)
	}

	for {
		c, err := listener.Accept()
		if err != nil {
			stderr.Print(err)
			continue
		}

		go func() {
			err := agent.ServeAgent(keyring, c)
			if err != nil && err != io.EOF {
				stderr.Print(err)
			}
		}()
	}
}
