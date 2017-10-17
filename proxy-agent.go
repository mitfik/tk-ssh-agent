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
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"net"
)

type proxykeyring struct {
	tkKeyRing    agent.Agent
	backendAgent agent.Agent
}

// NewBackendAgent - Proxy unknown identities to other agent
func NewBackendAgent(backend string) (agent.Agent, error) {
	sock, err := net.Dial("unix", backend)
	if err != nil {
		return nil, err
	}
	backendAgent := agent.NewClient(sock)

	return backendAgent, nil
}

// NewProxyAgent - Use TK signing for known TK identities and forward unknown
// ones to another agent
func NewProxyAgent(identities []TKIdentity, backend agent.Agent) (agent.Agent, error) {
	tkKeyRing := NewTKeyring(identities)

	return &proxykeyring{
		tkKeyRing:    tkKeyRing,
		backendAgent: backend,
	}, nil
}

func (r *proxykeyring) List() ([]*agent.Key, error) {
	tkList, err := r.tkKeyRing.List()
	if err != nil {
		return nil, err
	}

	backendList, err := r.backendAgent.List()
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

	signResult, err = r.backendAgent.Sign(key, data)
	if err != nil {
		return nil, err
	}
	return signResult, nil
}

func (r *proxykeyring) Add(key agent.AddedKey) error {
	return r.backendAgent.Add(key)
}

func (r *proxykeyring) Remove(key ssh.PublicKey) error {
	return r.backendAgent.Remove(key)
}

func (r *proxykeyring) RemoveAll() error {
	return r.backendAgent.RemoveAll()
}

func (r *proxykeyring) Lock(passphrase []byte) error {
	err := r.tkKeyRing.Lock(passphrase)
	if err != nil {
		return err
	}

	err = r.backendAgent.Lock(passphrase)
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

	err = r.backendAgent.Unlock(passphrase)
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

	backendSigners, err := r.backendAgent.Signers()
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
