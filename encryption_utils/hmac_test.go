package encryption_utils

import "testing"
import "github.com/orfjackal/gospec/src/gospec"

func TestHmacSpecs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in benchmark mode.")
		return
	}
	r := gospec.NewRunner()
	r.AddSpec(HmacSpecs)
	gospec.MainGoTest(r, t)
}

func HmacSpecs(c gospec.Context) {
	// Key for the hmac cypher:
	var hmac_key = []byte("aabbccddeeffgghh")

	// EncryptHmacSha1 Test

	c.Specify("[EncryptHmacSha1] Encrypts number", func() {
		value, err := EncryptHmacSha1("0.00", hmac_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(string(value), gospec.Equals, "c1583a958d49777291cbc54936a0781c50772363")
	})

	c.Specify("[EncryptHmacSha1] Encrypts number", func() {
		value, err := EncryptHmacSha1("0.12", hmac_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(string(value), gospec.Equals, "600be3455de48f65a8d8b7230a5dda36698ec63c")
	})

	c.Specify("[EncryptHmacSha1] Encrypts number", func() {
		value, err := EncryptHmacSha1("123.45", hmac_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(string(value), gospec.Equals, "a5447804a9c247b309e8c89d77fe282dc421c36b")
	})

	c.Specify("[EncryptHmacSha1] Encrypts number", func() {
		value, err := EncryptHmacSha1("567.89", hmac_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(string(value), gospec.Equals, "ca58de8290e7762607dc39e14b4339ff57c617d7")
	})

	// EncryptHmacSha256 Test

	c.Specify("[EncryptHmacSha256] Encrypts number", func() {
		value, err := EncryptHmacSha256("0.00", hmac_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(string(value), gospec.Equals, "f5e45805ddce2076fc203b3a727a3e97b1b242a186b03e44d451de82f14660ac")
	})

	c.Specify("[EncryptHmacSha256] Encrypts number", func() {
		value, err := EncryptHmacSha256("0.12", hmac_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(string(value), gospec.Equals, "f18dc4b6355782127ff01d816b61aa23e207ffd7266824da40cf18545d0a86a9")
	})

	c.Specify("[EncryptHmacSha256] Encrypts number", func() {
		value, err := EncryptHmacSha256("123.45", hmac_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(string(value), gospec.Equals, "4d2535554540c0780435185d3153da72a4d24d3a0276aced49baa93914cf3f6a")
	})

	c.Specify("[EncryptHmacSha256] Encrypts number", func() {
		value, err := EncryptHmacSha256("567.89", hmac_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(string(value), gospec.Equals, "c43ab5c5c825bd33171310687349a7520a5e334ecc4e153de32a8f4b598dc6bc")
	})

	// EncryptHmacMd5 Test

	c.Specify("[EncryptHmacMd5] Encrypts number", func() {
		value, err := EncryptHmacMd5("0.00", hmac_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(string(value), gospec.Equals, "1136b318918abfd465af50a8f1c6b6f0")
	})

	c.Specify("[EncryptHmacMd5] Encrypts number", func() {
		value, err := EncryptHmacMd5("0.12", hmac_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(string(value), gospec.Equals, "d8683d13fd01c9f08861568da561e837")
	})

	c.Specify("[EncryptHmacMd5] Encrypts number", func() {
		value, err := EncryptHmacMd5("123.45", hmac_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(string(value), gospec.Equals, "0f7464c08684ea95bce22b0e10fe9e21")
	})

	c.Specify("[EncryptHmacMd5] Encrypts number", func() {
		value, err := EncryptHmacMd5("567.89", hmac_key)
		c.Expect(err, gospec.Equals, nil)
		c.Expect(string(value), gospec.Equals, "6c6f09c519c7591e795520323a8fbebb")
	})

}

func Benchmark_Encryption_ToHmacSha1(b *testing.B) {
	var hmac_key = []byte("aabbccddeeffgghh")

	for i := 0; i < b.N; i++ {
		EncryptHmacSha1("567.89", hmac_key)
	}
}

func Benchmark_Encryption_ToHmacSha256(b *testing.B) {
	var hmac_key = []byte("aabbccddeeffgghh")

	for i := 0; i < b.N; i++ {
		EncryptHmacSha256("567.89", hmac_key)
	}
}

func Benchmark_Encryption_ToHmacMd5(b *testing.B) {
	var hmac_key = []byte("aabbccddeeffgghh")

	for i := 0; i < b.N; i++ {
		EncryptHmacMd5("567.89", hmac_key)
	}
}
