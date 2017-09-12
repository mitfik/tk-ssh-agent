package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"
)

func encodeBase64Url(src []byte) []byte {
	dst := make([]byte, base64.RawURLEncoding.EncodedLen(len(src)))
	base64.RawURLEncoding.Encode(dst, src)
	return dst
}

func getHmacJWS(url string, identity TKIdentity) ([]byte, error) {
	header, err := json.Marshal(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(map[string]interface{}{
		"sub": identity.clientID,
		"aud": url,
		// Three minute timouts for ssh logins
		"exp": int32(time.Now().Unix()) + 180,
	})
	if err != nil {
		return nil, err
	}

	joseBase64 := encodeBase64Url(header)
	payloadBase64 := encodeBase64Url(payload)

	secret := []byte(identity.clientSecret)

	jws := append(joseBase64, byte('.'))
	jws = append(jws, payloadBase64...)

	mac := hmac.New(sha256.New, secret)
	mac.Write(jws)
	digest := mac.Sum(nil)

	digestBase64 := encodeBase64Url(digest)
	jws = append(jws, byte('.'))
	jws = append(jws, digestBase64...)

	return jws, nil
}

// HTTPGet - Send GET request to RP
func HTTPGet(identity TKIdentity, requestPath string, params map[string]string) (map[string]interface{}, error) {
	client := &http.Client{}

	req, err := http.NewRequest("GET", identity.rpURL+requestPath, nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	for key, value := range params {
		q.Add(key, value)
	}
	req.URL.RawQuery = q.Encode()

	jws, err := getHmacJWS(req.URL.String(), identity)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+string(jws))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
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
