package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
)

// TKIdentity is the intermediate representation of configuration data
// used for initializing internal data structures
type TKIdentity struct {
	rpURL        string // The relying party to send login requests to
	pubkey       []byte // User public key
	clientID     string // ID used for HMAC auth with relying party
	clientSecret string // Secret used for HMAC auth with relying party
	addr         string // Subject address
}

func fieldError(field string) error {
	return errors.New(field + "does not exist in identity")
}

// ReadConfig ...
func ReadConfig(path string) ([]TKIdentity, error) {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(contents, &data); err != nil {
		return nil, err
	}

	var tkIdentities []TKIdentity
	for key, values := range data {
		v := values.(map[string]interface{})
		rpURL := v["rpURL"]
		if rpURL == nil {
			return nil, fieldError("rpURL")
		}

		clientID := v["clientId"]
		if clientID == nil {
			return nil, fieldError("clientId")
		}

		clientSecret := v["clientSecret"]
		if clientSecret == nil {
			return nil, fieldError("clientSecret")
		}

		pub := []byte(key)

		addr, err := UserPubKeyHexToAddress(pub)
		if err != nil {
			return nil, err
		}

		identity := TKIdentity{
			pubkey:       []byte(key),
			rpURL:        rpURL.(string),
			clientID:     clientID.(string),
			clientSecret: clientSecret.(string),
			addr:         addr,
		}

		tkIdentities = append(tkIdentities, identity)
	}

	return tkIdentities, nil
}
