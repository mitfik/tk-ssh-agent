package main

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
)

type trustedKeySigner struct {
	pub      ssh.PublicKey
	identity TKIdentity
}

type asn1signature struct {
	R, S *big.Int
}

// Encode data with base64(data)
func encodeData(data []byte) []byte {
	b64 := base64.StdEncoding
	base64Data := make([]byte, b64.EncodedLen(len(data)))
	b64.Encode(base64Data, data)
	return base64Data
}

// NewTKSigner returns a Signer that signs with the given something
func NewTKSigner(identity TKIdentity) (ssh.Signer, error) {
	pub, err := UserPubKeyHexToSSHPubKey(identity.pubkey)
	if err != nil {
		panic(err)
	}

	return &trustedKeySigner{pub, identity}, nil
}

func (s *trustedKeySigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	b := sha256.Sum256(data)
	encodedData := encodeData(b[:])

	// TODO: Use https://github.com/0xAX/notificator (or other libnotify thingy) for displaying OTP
	// TODO: Get callback URL from /sshlogin call and use that for OTP
	otp := OneTimePassword(encodedData, encodedData)
	fmt.Println(fmt.Sprintf("Verify this OTP on your device: %s (TODO: UI integration)", otp))

	// TODO: Authenticated HTTP call
	// TODO: Different flow, needs callback url
	resp, err := http.Get("http://localhost:3001/sshlogin?nonce=" + url.QueryEscape(string(encodedData)) + "&expiry=31337&subjectaddress=" + s.identity.addr)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var dat map[string]interface{}
	if err := json.Unmarshal(body, &dat); err != nil {
		return nil, err
	}

	sig, err := base64.StdEncoding.DecodeString(dat["data"].(string))
	if err != nil {
		return nil, err
	}

	asn1Sig := new(asn1signature)
	rest, err := asn1.Unmarshal(sig, asn1Sig)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("ssh: rubbish after signature (malformed signature)")
	}
	signature := ssh.Marshal(asn1Sig)

	return &ssh.Signature{Format: s.pub.Type(), Blob: signature}, nil
}

func (s *trustedKeySigner) PublicKey() ssh.PublicKey {
	return s.pub
}
