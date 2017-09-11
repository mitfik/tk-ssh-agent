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
	pub ssh.PublicKey
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
func NewTKSigner(pub ssh.PublicKey, signer ssh.Signer) (ssh.Signer, error) {

	// Pubkey hex: 04f311e2786e5a34d1a66b7d888bdb32ea55f467ca5d2e70e023c1379bef43b3a4eb97f950d8c1acfbad21c93b6645dcba5c50683b8c5f9860e3ba6800e84617ef
	// Ssh header: \x00\x00\x00\x13ecdsa-sha2-nistp256\x00\x00\x00\x08nistp256\x00\x00\x00A
	// Base64 encoded pubkey: AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPMR4nhuWjTRpmt9iIvbMupV9GfKXS5w4CPBN5vvQ7Ok65f5UNjBrPutIck7ZkXculxQaDuMX5hg47poAOhGF+8=

	// Pub bytes (hardware)
	pubBytes := []byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJIxwbp33CnsYhiK52bIRV9++5ix7HcR1vMzPC2JOJcMMB95+rdwxXABTDqqLsK0D8+wNSD8UDpvbtRPjafpN3A= 0x00087531644ec07b2cb45cea5f273eb8cba93846")

	// Pub bytes (js emu)
	// pubBytes := []byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBElA9G3/6RZ0T7F+6ambRkbjeG4CR1bF047FaO8FPsNsm3OMJRN0fBNhrstT7TLdNDoOvtWMo0B0O2s/PX3GDJg= 0x00087531644ec07b2cb45cea5f273eb8cba93846")

	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		return nil, err
	}

	return &trustedKeySigner{pub}, nil
}

func (s *trustedKeySigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	b := sha256.Sum256(data)
	encodedData := encodeData(b[:])

	// TODO: Use https://github.com/0xAX/notificator (or other libnotify thingy) for displaying OTP
	// TODO: Get callback URL from /sshlogin call and use that for OTP
	otp := OneTimePassword(encodedData, encodedData)
	fmt.Println(fmt.Sprintf("Verify this OTP on your device: %s (TODO: UI integration)", otp))

	// TODO: Authenticated HTTP call
	resp, err := http.Get("http://localhost:3001/sshlogin?nonce=" + url.QueryEscape(string(encodedData)) + "&expiry=31337&subjectaddress=0x00087531644ec07b2cb45cea5f273eb8cba93846")
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
		return nil, errors.New("ssh: rubbish after signature")
	}
	signature := ssh.Marshal(asn1Sig)

	return &ssh.Signature{Format: s.pub.Type(), Blob: signature}, nil
}

func (s *trustedKeySigner) PublicKey() ssh.PublicKey {
	return s.pub
}
