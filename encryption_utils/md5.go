package encryption_utils

import "crypto/md5"
import "fmt"
import "io"

func EncryptMd5(str string) string {
	hash := md5.New()
	io.WriteString(hash, str)

	return (fmt.Sprintf("%x", hash.Sum(nil)))
}
