package encryption_utils

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
)

// Encryption

func EncryptHmacSha1(str string, key []byte) (string, error) {
	mac := hmac.New(sha1.New, key)
	io.WriteString(mac, str)

	return (fmt.Sprintf("%x", mac.Sum(nil))), nil
}

func EncryptHmacSha256(str string, key []byte) (string, error) {
	mac := hmac.New(sha256.New, key)
	io.WriteString(mac, str)

	return (fmt.Sprintf("%x", mac.Sum(nil))), nil
}

func EncryptHmacMd5(str string, key []byte) (string, error) {
	mac := hmac.New(md5.New, key)
	io.WriteString(mac, str)

	return (fmt.Sprintf("%x", mac.Sum(nil))), nil
}
