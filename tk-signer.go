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
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
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

	otp := OneTimePassword(encodedData, []byte(callbackURL.(string)))
	Notify(otp)

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
