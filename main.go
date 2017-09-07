package main

import (
	"fmt"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"log"
	"net"
	"os"
)

func main() {
	stderr := log.New(os.Stderr, "", 0)
	keyring := NewTKeyring()
	listener, err := net.Listen("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		panic(fmt.Sprintf("Listen error: %s", err))
	}
	defer listener.Close()

	// TODO: Parse config file and add identities from there
	err = keyring.Add(agent.AddedKey{
		PrivateKey:   nil, // NO!
		Certificate:  nil, // All cert details are stored on users phone
		Comment:      "0x3705e3d8b450dcb0826b8d9e7cefbd99db2f417a",
		LifetimeSecs: 0,
	})
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
