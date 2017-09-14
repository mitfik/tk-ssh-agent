package main

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path"
)

func main() {
	stderr := log.New(os.Stderr, "", 0)

	usr, err := user.Current()
	if err != nil {
		panic(err)
	}

	configPath := flag.String("config",
		path.Join(usr.HomeDir, ".config", "tk-ssh.json"),
		"/path/to/conf.json")
	outputShell := flag.String("shell", "bash", "(bash|fish)")
	quiet := flag.Bool("quiet", false, "Dont output shell command for config")
	sockPath := flag.String("socket", "/tmp/tk-ssh-auth.sock", "Path to unix domain socket")
	flag.Parse()

	if !*quiet {
		switch {
		case *outputShell == "bash":
			fmt.Println(fmt.Sprintf("export SSH_AUTH_SOCK='%s'", *sockPath))
		case *outputShell == "fish":
			fmt.Println(fmt.Sprintf("setenv SSH_AUTH_SOCK '%s'", *sockPath))
		}
	}

	listener, err := net.Listen("unix", *sockPath)
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
	go func() {
		for _ = range c {
			cleanup()
			os.Exit(0)
		}
	}()
	defer cleanup()

	identities, err := ReadConfig(*configPath)
	if err != nil {
		stderr.Println(fmt.Sprintf("Missing configuration in '%s'", *configPath))
		os.Exit(1)
	}

	keyring := NewTKeyring(identities)
	if err != nil {
		log.Panic(err)
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
