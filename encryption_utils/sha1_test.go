package encryption_utils

import "testing"
import "github.com/orfjackal/gospec/src/gospec"

func TestSha1Specs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in benchmark mode.")
		return
	}
	r := gospec.NewRunner()
	r.AddSpec(Sha1Specs)
	gospec.MainGoTest(r, t)
}

func Sha1Specs(c gospec.Context) {

	c.Specify("Encrypts number with Sha1", func() {
		value := EncryptSha1("0.00")
		c.Expect(string(value), gospec.Equals, "22cf82b68b95049bffb91128349ccc312a460b10")
	})

	c.Specify("Encrypts number with Sha1", func() {
		value := EncryptSha1("0.12")
		c.Expect(string(value), gospec.Equals, "5b08b72ad1fe7c69fbbfe26417351f4e7c11717c")
	})

	c.Specify("Encrypts number with Sha1", func() {
		value := EncryptSha1("123.45")
		c.Expect(string(value), gospec.Equals, "22f8b438ad7e89300b51d88684f3f0b9fa1d7a32")
	})

	c.Specify("Encrypts number with Sha1", func() {
		value := EncryptSha1("567.89")
		c.Expect(string(value), gospec.Equals, "9f75f0552a875755b455de6e392bd26c6953ab41")
	})

}

func Benchmark_Encryption_ToSha1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		EncryptSha1("567.89")
	}
}
