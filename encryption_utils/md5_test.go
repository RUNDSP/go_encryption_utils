package encryption_utils

import "testing"
import "github.com/orfjackal/gospec/src/gospec"

func TestMd5Specs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in benchmark mode.")
		return
	}
	r := gospec.NewRunner()
	r.AddSpec(Md5Specs)
	gospec.MainGoTest(r, t)
}

func Md5Specs(c gospec.Context) {
	c.Specify("Encrypts number with Md5", func() {
		value := EncryptMd5("0.00")
		c.Expect(string(value), gospec.Equals, "f7ddd489ab0a82567b241b05971cbdb3")

		value = EncryptMd5("0.12")
		c.Expect(string(value), gospec.Equals, "b1659515b9d1a59ebbc790e01084a8f0")

		value = EncryptMd5("123.45")
		c.Expect(string(value), gospec.Equals, "a9695328e70947a7f087357eea400488")

		value = EncryptMd5("567.89")
		c.Expect(string(value), gospec.Equals, "0bed9bf3fcd897dab0c95710fdeca756")
	})
}

func Benchmark_Encryption_ToMd5(b *testing.B) {
	for i := 0; i < b.N; i++ {
		EncryptMd5("567.89")
	}
}
