package main

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"net"
)

type proxykeyring struct {
	tkKeyRing        agent.Agent
	backendAgentSock string
}

func newBackendAgent(backend string) (agent.Agent, error) {
	sock, err := net.Dial("unix", backend)
	if err != nil {
		return nil, err
	}
	backendAgent := agent.NewClient(sock)

	return backendAgent, nil
}

// NewProxyAgent - Use TK signing for known TK identities and forward unknown
// ones to another agent
func NewProxyAgent(identities []TKIdentity, backend string) (agent.Agent, error) {
	tkKeyRing := NewTKeyring(identities)

	return &proxykeyring{
		tkKeyRing:        tkKeyRing,
		backendAgentSock: backend,
	}, nil
}

func (r *proxykeyring) List() ([]*agent.Key, error) {
	tkList, err := r.tkKeyRing.List()
	if err != nil {
		return nil, err
	}

	backendAgent, err := newBackendAgent(r.backendAgentSock)
	if err != nil {
		return nil, err
	}

	backendList, err := backendAgent.List()
	if err != nil {
		return nil, err
	}

	var keys []*agent.Key
	for _, key := range tkList {
		keys = append(keys, key)
	}
	for _, key := range backendList {
		keys = append(keys, key)
	}

	return keys, nil
}

func (r *proxykeyring) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	signResult, err := r.tkKeyRing.Sign(key, data)
	if signResult != nil {
		return signResult, nil
	}
	if err != nil && err != ErrSignerNotFound {
		return nil, err
	}

	backendAgent, err := newBackendAgent(r.backendAgentSock)
	if err != nil {
		return nil, err
	}

	signResult, err = backendAgent.Sign(key, data)
	if err != nil {
		return nil, err
	}
	return signResult, nil
}

func (r *proxykeyring) Add(key agent.AddedKey) error {
	backendAgent, err := newBackendAgent(r.backendAgentSock)
	if err != nil {
		return err
	}
	return backendAgent.Add(key)
}

func (r *proxykeyring) Remove(key ssh.PublicKey) error {
	backendAgent, err := newBackendAgent(r.backendAgentSock)
	if err != nil {
		return err
	}
	return backendAgent.Remove(key)
}

func (r *proxykeyring) RemoveAll() error {
	backendAgent, err := newBackendAgent(r.backendAgentSock)
	if err != nil {
		return err
	}
	return backendAgent.RemoveAll()
}

func (r *proxykeyring) Lock(passphrase []byte) error {
	err := r.tkKeyRing.Lock(passphrase)
	if err != nil {
		return err
	}

	backendAgent, err := newBackendAgent(r.backendAgentSock)
	if err != nil {
		return err
	}

	err = backendAgent.Lock(passphrase)
	if err != nil {
		return err
	}

	return nil
}

func (r *proxykeyring) Unlock(passphrase []byte) error {
	err := r.tkKeyRing.Unlock(passphrase)
	if err != nil {
		return err
	}

	backendAgent, err := newBackendAgent(r.backendAgentSock)
	if err != nil {
		return err
	}

	err = backendAgent.Unlock(passphrase)
	if err != nil {
		return err
	}

	return nil
}

func (r *proxykeyring) Signers() ([]ssh.Signer, error) {
	tkSigners, err := r.tkKeyRing.Signers()
	if err != nil {
		return nil, err
	}

	backendAgent, err := newBackendAgent(r.backendAgentSock)
	if err != nil {
		return nil, err
	}

	backendSigners, err := backendAgent.Signers()
	if err != nil {
		return nil, err
	}

	var signers []ssh.Signer
	for _, signer := range tkSigners {
		signers = append(signers, signer)
	}
	for _, signer := range backendSigners {
		signers = append(signers, signer)
	}

	return signers, nil
}
