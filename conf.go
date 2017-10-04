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

func hasKey(configData map[string]interface{}, key string) bool {
	val, ok := configData[key]
	return ok && val != nil
}

// ReadConfigRaw ...
func ReadConfigRaw(configPath string) map[string]interface{} {
	data := make(map[string]interface{})

	contents, err := ioutil.ReadFile(configPath)
	if err != nil {
		return data
	}

	if err := json.Unmarshal(contents, &data); err != nil {
		panic(err)
	}

	return data
}

// ReadConfigExtra ...
func ReadConfigExtra(configPath string) map[string]interface{} {
	jsonData := ReadConfigRaw(configPath)
	var configData map[string]interface{}
	if hasKey(jsonData, "config") {
		configData = jsonData["config"].(map[string]interface{})
	} else {
		configData = make(map[string]interface{})
	}
	return configData
}

// WriteConfigRaw ...
func WriteConfigRaw(configPath string, config map[string]interface{}) error {
	outputJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(configPath, outputJSON, 0600)
	if err != nil {
		return err
	}

	return nil
}

// ReadConfig ...
func ReadConfig(path string) ([]TKIdentity, error) {
	data := ReadConfigRaw(path)

	var tkIdentities []TKIdentity
	for key, values := range data {

		if key == "config" {
			continue
		}

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
