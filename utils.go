package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
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
