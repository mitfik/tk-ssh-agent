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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
		"iss": identity.clientID,
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

	if resp.StatusCode != 200 {
		err = fmt.Errorf("RP returned status code %d", resp.StatusCode)
		return nil, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return data, nil
}
