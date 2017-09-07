package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"log"
	"sync"
)

type privKey struct {
	signer  ssh.Signer
	comment string
}

type keyring struct {
	mutex sync.Mutex
	keys  []privKey

	locked     bool
	passphrase []byte
}

var errLocked = errors.New("agent: locked")

// NewTKeyring returns an Agent that holds keys in memory.  It is safe
// for concurrent use by multiple goroutines.
func NewTKeyring() agent.Agent {
	return &keyring{}
}

func (r *keyring) List() ([]*agent.Key, error) {
	log.Println("List")
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.locked {
		// section 2.7: locked agents return empty.
		return nil, nil
	}

	var ids []*agent.Key
	for _, k := range r.keys {
		pub := k.signer.PublicKey()
		ids = append(ids, &agent.Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: k.comment})
	}
	return ids, nil
}

func (r *keyring) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.locked {
		return nil, errLocked
	}

	wanted := key.Marshal()
	for _, k := range r.keys {
		if bytes.Equal(k.signer.PublicKey().Marshal(), wanted) {
			return k.signer.Sign(rand.Reader, data)
		}
	}

	return nil, errors.New("not found")
}

func (r *keyring) Add(key agent.AddedKey) error {
	// TODO: Split add into internal method and return error
	// Adding via agent protocol should not be supported
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if key.LifetimeSecs > 0 {
		return errors.New("Key lifetimes not supported")
	}

	signer, err := NewTKSigner(nil, nil)
	if err != nil {
		return err
	}

	p := privKey{
		signer:  signer,
		comment: key.Comment,
	}
	r.keys = append(r.keys, p)

	return nil
}

func (r *keyring) Remove(key ssh.PublicKey) error {
	return errors.New("Removing not supported, edit config file and reload")
}

func (r *keyring) RemoveAll() error {
	return errors.New("Removing not supported, edit config file and reload")
}

func (r *keyring) Lock(passphrase []byte) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.locked {
		return errLocked
	}

	r.locked = true
	r.passphrase = passphrase
	return nil
}

func (r *keyring) Unlock(passphrase []byte) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if !r.locked {
		return errors.New("agent: not locked")
	}
	if len(passphrase) != len(r.passphrase) || 1 != subtle.ConstantTimeCompare(passphrase, r.passphrase) {
		return fmt.Errorf("agent: incorrect passphrase")
	}

	r.locked = false
	r.passphrase = nil
	return nil
}

func (r *keyring) Signers() ([]ssh.Signer, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.locked {
		return nil, errLocked
	}

	s := make([]ssh.Signer, 0, len(r.keys))
	for _, k := range r.keys {
		s = append(s, k.signer)
	}
	return s, nil
}
