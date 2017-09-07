package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
)

type trustedKeySigner struct {
	pub ssh.PublicKey
}

// Encode data with hex(base64(data))
func encodeData(data []byte) []byte {
	b64 := base64.StdEncoding
	base64Data := make([]byte, b64.EncodedLen(len(data)))
	b64.Encode(base64Data, data)

	hexData := make([]byte, hex.EncodedLen(len(base64Data)))
	hex.Encode(hexData, base64Data)

	return hexData
}

// NewTKSigner returns a Signer that signs with the given something
func NewTKSigner(pub ssh.PublicKey, signer ssh.Signer) (ssh.Signer, error) {

	// Pubkey hex: 04f311e2786e5a34d1a66b7d888bdb32ea55f467ca5d2e70e023c1379bef43b3a4eb97f950d8c1acfbad21c93b6645dcba5c50683b8c5f9860e3ba6800e84617ef
	// Ssh header: \x00\x00\x00\x13ecdsa-sha2-nistp256\x00\x00\x00\x08nistp256\x00\x00\x00A
	// Base64 encoded pubkey: AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPMR4nhuWjTRpmt9iIvbMupV9GfKXS5w4CPBN5vvQ7Ok65f5UNjBrPutIck7ZkXculxQaDuMX5hg47poAOhGF+8=

	pubBytes := []byte("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPMR4nhuWjTRpmt9iIvbMupV9GfKXS5w4CPBN5vvQ7Ok65f5UNjBrPutIck7ZkXculxQaDuMX5hg47poAOhGF+8= 0x3705e3d8b450dcb0826b8d9e7cefbd99db2f417a")

	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		return nil, err
	}

	return &trustedKeySigner{pub}, nil
}

func (s *trustedKeySigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	encodedData := encodeData(data)

	// TODO: Can we somehow print this in the ssh session output rather than stdout in the agent?
	// Maybe spin off a ui that shows the thing
	otp := OneTimePassword(encodedData, encodedData)
	fmt.Println(fmt.Sprintf("Verify this OTP on your device: %s", otp))

	return nil, errors.New("Signing not fully implemented")
}

func (s *trustedKeySigner) PublicKey() ssh.PublicKey {
	return s.pub
}
