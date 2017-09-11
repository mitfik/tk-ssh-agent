package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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

// NewTKeyring returns an Agent that holds keys in the Trusted Key app.
// It is safe for concurrent use by multiple goroutines.
func NewTKeyring(identities []TKIdentity) agent.Agent {
	r := &keyring{}

	for _, identity := range identities {
		signer, err := NewTKSigner(identity)
		if err != nil {
			panic(err)
		}

		p := privKey{
			signer:  signer,
			comment: identity.addr,
		}
		r.keys = append(r.keys, p)
	}

	return r
}

func (r *keyring) List() ([]*agent.Key, error) {
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
	if r.locked {
		return nil, errLocked
	}
	r.mutex.Lock()

	wanted := key.Marshal()
	var signer ssh.Signer
	for _, k := range r.keys {
		if bytes.Equal(k.signer.PublicKey().Marshal(), wanted) {
			signer = k.signer
			break
		}
	}

	// Unlock before we actually call sign to prevent deadlocks
	r.mutex.Unlock()
	if signer == nil {
		return nil, errors.New("signer for public key not found")
	}

	return signer.Sign(rand.Reader, data)
}

func (r *keyring) Add(key agent.AddedKey) error {
	return errors.New("Removing not supported, edit config file and reload")
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
