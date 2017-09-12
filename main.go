package main

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"log"
	"net"
	"os"
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
	flag.Parse()

	sockPath, envSet := os.LookupEnv("SSH_AUTH_SOCK")
	if !envSet {
		sockPath = "/tmp/tk-ssh-auth.sock"
	}

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		panic(fmt.Sprintf("Listen error: %s", err))
	}
	defer func() {
		err := listener.Close()
		if err != nil {
			stderr.Println("Could not close socket file")
		}

		err = os.Remove(sockPath)
		if err != nil {
			stderr.Println("Could not remove socket file")
		}
	}()

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
