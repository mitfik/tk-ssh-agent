package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os/user"
	"path"
)

func getLoginQueryParams(rpURL string, client *http.Client) (string, string, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/login/trustedkey/", rpURL), nil)
	if err != nil {
		return "", "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	if location == "" {
		return "", "", errors.New("Missing location header")
	}

	url, err := url.ParseRequestURI(location)
	if err != nil {
		return "", "", err
	}

	return fmt.Sprintf("%s://%s", url.Scheme, url.Host), url.RawQuery, nil
}

func submitLogin(walletURL string, username string, queryParams string) (map[string]string, error) {
	walletSubmitURL, err := url.ParseRequestURI(fmt.Sprintf("%s/oauth/IDentify/submitLogin", walletURL))
	if err != nil {
		return nil, err
	}

	q := walletSubmitURL.Query()
	q.Set("query", queryParams)
	q.Set("username", username)
	walletSubmitURL.RawQuery = q.Encode()

	resp, err := http.Get(walletSubmitURL.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Server returned HTTP status code %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jsonData map[string]interface{}
	if err := json.Unmarshal(body, &jsonData); err != nil {
		return nil, err
	}

	ret := make(map[string]string)
	data := jsonData["data"].(map[string]interface{})
	ret["nonce"] = data["nonce"].(string)
	ret["checksum"] = data["checksum"].(string)

	return ret, nil
}

func waitLogin(walletURL string, nonce string) (string, error) {
	waitURL, err := url.ParseRequestURI(fmt.Sprintf("%s/oauth/IDentify/waitLogin", walletURL))
	if err != nil {
		return "", err
	}

	q := waitURL.Query()
	q.Set("nonce", nonce)
	waitURL.RawQuery = q.Encode()

	resp, err := http.Get(waitURL.String())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Timeout, retry
	if resp.StatusCode == 408 {
		return waitLogin(walletURL, nonce)
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Server returned HTTP status code %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var jsonData map[string]interface{}
	if err := json.Unmarshal(body, &jsonData); err != nil {
		return "", err
	}

	data := jsonData["data"].(map[string]interface{})

	return data["url"].(string), nil
}

func getCredentialConfig(rpURL string, client *http.Client) (map[string]interface{}, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/credential_add", rpURL), nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Server returned HTTP status code %d (login not successful)", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return data, nil
}

func login(username string, rpURL string) (map[string]interface{}, error) {
	cookiejar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Jar: cookiejar,
	}

	walletURL, queryParams, err := getLoginQueryParams(rpURL, client)
	if err != nil {
		return nil, err
	}

	loginData, err := submitLogin(walletURL, username, queryParams)
	if err != nil {
		return nil, err
	}

	fmt.Println(fmt.Sprintf("Verify this OTP on your device: %s", loginData["checksum"]))

	loginURL, err := waitLogin(walletURL, loginData["nonce"])
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", loginURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	defer logout(rpURL, client)

	credentials, err := getCredentialConfig(rpURL, client)
	if err != nil {
		return nil, err
	}

	return credentials, nil
}

func logout(rpURL string, client *http.Client) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/logout", rpURL), nil)
	if err != nil {
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// EnrollMain - Run enroll main loop
func EnrollMain(username string, rpURLFlag string, configPath string) {
	// Normalise relying party URL
	rpURL, err := url.ParseRequestURI(rpURLFlag)
	if err != nil {
		panic(err)
	}

	config := ReadConfigRaw(configPath)

	credentials, err := login(username, fmt.Sprintf("%s://%s", rpURL.Scheme, rpURL.Host))
	if err != nil {
		panic(err)
	}

	for k, v := range credentials {
		pubkeyBytes := []byte(k)

		addr, err := UserPubKeyHexToAddress(pubkeyBytes)
		if err != nil {
			panic(err)
		}

		key, err := UserPubKeyHexToSSHPubKey(pubkeyBytes)
		if err != nil {
			panic(err)
		}

		pub := ssh.MarshalAuthorizedKey(key)
		if err != nil {
			panic(err)
		}

		usr, err := user.Current()
		if err != nil {
			panic(err)
		}

		authorizedKey := fmt.Sprintf("%s %s", string(pub[:len(pub)-1]), string(addr))
		outFile := path.Join(usr.HomeDir, ".ssh", fmt.Sprintf("tk_%s.pub", string(addr)))
		err = ioutil.WriteFile(outFile, []byte(authorizedKey), 0666)
		if err != nil {
			fmt.Println(fmt.Sprintf("Couldn't write public key file: %s", authorizedKey))
		} else {
			fmt.Println(fmt.Sprintf("You can now run \"ssh-copy-id -f -i %s user@host\" to copy your credential to a remote server", outFile))
		}

		config[k] = v
	}

	err = WriteConfigRaw(configPath, config)
	if err != nil {
		panic(err)
	}

	fmt.Println("Credential enrolled")
}
