package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
)

func readInt32(data []byte) (ret int32) {
	buf := bytes.NewBuffer(data)
	binary.Read(buf, binary.BigEndian, &ret)
	return ret
}

// OneTimePassword is an HMAC-based One-time Password Algorithm implementation
func OneTimePassword(key []byte, message []byte) (ret string) {
	hasher := hmac.New(sha1.New, key)
	hasher.Write(message)
	hash := hasher.Sum(nil)

	offset := hash[len(hash)-1] & 15
	truncatedHash := fmt.Sprint(readInt32(hash[offset:offset+4]) & 0x7FFFFFFF)
	paddedHash := "00000" + truncatedHash

	return paddedHash[len(paddedHash)-6 : len(paddedHash)]
}

// UserPubKeyHexToAddress ...
func UserPubKeyHexToAddress(pub []byte) (string, error) {
	pubInput := pub[2:]
	blob := make([]byte, hex.DecodedLen(len(pubInput)))
	_, err := hex.Decode(blob, pubInput)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256(blob)
	return "0x" + hex.EncodeToString(digest[:])[2*12:], nil
}

// UserPubKeyHexToSSHPubKey ...
func UserPubKeyHexToSSHPubKey(pub []byte) (ssh.PublicKey, error) {
	blob := make([]byte, hex.DecodedLen(len(pub)))
	_, err := hex.Decode(blob, pub)
	if err != nil {
		return nil, err
	}

	ecPub := new(ecdsa.PublicKey)
	ecPub.Curve = elliptic.P256()
	ecPub.X, ecPub.Y = elliptic.Unmarshal(ecPub.Curve, blob)
	if ecPub.X == nil || ecPub.Y == nil {
		return nil, errors.New("ssh: invalid curve point")
	}

	return ssh.NewPublicKey(ecPub)
}
