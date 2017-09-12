package main

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"math/big"
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

	// Send signature request
	resp, err := HTTPGet(s.identity, "/sshlogin", map[string]string{
		"nonce":          string(encodedData),
		"subjectaddress": s.identity.addr,
	})
	if err != nil {
		return nil, err
	}

	callbackURL := resp["callbackUrl"]
	if callbackURL == nil {
		return nil, errors.New("Missing callback url from server response")
	}
	loginRequestID := resp["loginRequestId"]
	if loginRequestID == nil {
		return nil, errors.New("Missing loginRequestId url from server response")
	}

	// TODO: Use https://github.com/0xAX/notificator (or other libnotify thingy) for displaying OTP
	// TODO: Get callback URL from /sshlogin call and use that for OTP
	otp := OneTimePassword(encodedData, []byte(callbackURL.(string)))
	fmt.Println(fmt.Sprintf("Verify this OTP on your device: %s (TODO: UI integration)", otp))

	resp, err = HTTPGet(s.identity, "/sshloginPart2", map[string]string{
		"loginRequestId": loginRequestID.(string),
	})
	if err != nil {
		return nil, err
	}

	signatureResp := resp["signature"]
	if signatureResp == nil {
		return nil, errors.New("Missing signature from server response")
	}

	sig, err := base64.StdEncoding.DecodeString(signatureResp.(string))
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
