package encryption_utils

import "testing"
import "github.com/orfjackal/gospec/src/gospec"

func TestBlowfishSpecs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in benchmark mode.")
		return
	}
	r := gospec.NewRunner()
	r.AddSpec(BlowfishSpecs)
	gospec.MainGoTest(r, t)
}

func BlowfishSpecs(c gospec.Context) {
	// Key for the blowfish cypher:
	var blowfish_key = []byte("aabbccddeeffgghh")

	c.Specify("Encrypts number with Blowfish", func() {
		value, err := EncryptBlowfish("0.00", blowfish_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(value, gospec.Equals, string("0285B20516E533AA"))
	})

	c.Specify("Encrypts number with Blowfish", func() {
		value, err := EncryptBlowfish("0.12", blowfish_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(value, gospec.Equals, string("599B4625D7390640"))
	})

	c.Specify("Encrypts number with Blowfish", func() {
		value, err := EncryptBlowfish("123.45", blowfish_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(value, gospec.Equals, string("91CCD93E8EBB89BF"))
	})

	c.Specify("Encrypts number with Blowfish", func() {
		value, err := EncryptBlowfish("567.89", blowfish_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(value, gospec.Equals, string("49FA050B4F8E735E"))
	})

	c.Specify("Decrypts Price with Blowfish", func() {
		value, err := DecryptBlowfish("0285B20516E533AA", blowfish_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(value, gospec.Equals, ("0.00"))
	})

	c.Specify("Decrypts Price with Blowfish", func() {
		value, err := DecryptBlowfish("599B4625D7390640", blowfish_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(value, gospec.Equals, ("0.12"))
	})

	c.Specify("Decrypts Price with Blowfish", func() {
		value, err := DecryptBlowfish("91CCD93E8EBB89BF", blowfish_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(value, gospec.Equals, ("123.45"))
	})

	c.Specify("Decrypts Price with Blowfish", func() {
		value, err := DecryptBlowfish("49FA050B4F8E735E", blowfish_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(value, gospec.Equals, ("567.89"))
	})
}

func Benchmark_Encryption_ToBlowfish(b *testing.B) {
	var blowfish_key = []byte("aabbccddeeffgghh")

	for i := 0; i < b.N; i++ {
		EncryptBlowfish("0.00", blowfish_key)
	}
}

func Benchmark_Encryption_FromBlowfish(b *testing.B) {
	var blowfish_key = []byte("aabbccddeeffgghh")

	for i := 0; i < b.N; i++ {
		DecryptBlowfish("B9E2CCC1A222158F", blowfish_key)
	}
}
