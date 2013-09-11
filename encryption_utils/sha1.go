package encryption_utils

import "crypto/sha1"
import "fmt"
import "io"

func EncryptSha1(str string) string {
	hash := sha1.New()
	io.WriteString(hash, str)

	return (fmt.Sprintf("%x", hash.Sum(nil)))
}
