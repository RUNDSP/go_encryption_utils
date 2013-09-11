package encryption_utils

import "fmt"
import "encoding/hex"
import "errors"
import "strings"
import "code.google.com/p/go.crypto/blowfish"

//
// Encrypt the byte array with Blowfish
//
func EncryptBlowfish(str string, blowfish_key []byte) (string, error) {
	as_bytes := []byte(str)

	// Max of 8 bytes
	if len(as_bytes) > 8 {
		return "", errors.New(fmt.Sprintf("Input string is too long for blowfish! Max of 8 characters, str = %s", str))
	}

	// 8-Byte Buffers:
	input := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	output := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	// Write the bytes to the "input" buffer
	copy(input, as_bytes)

	// Create the blowfish cypher
	cypher, err := blowfish.NewCipher(blowfish_key)
	if nil != err {
		return "", err
	}

	// Encrypt the buffer
	cypher.Encrypt(output, input)

	// Convert the byte array back to a string
	return strings.ToUpper(hex.EncodeToString(output)), nil
}

func DecryptBlowfish(str string, blowfish_key []byte) (string, error) {
	as_bytes, err := hex.DecodeString(str)
	if nil != err {
		return "", err
	}

	// Exactly 8 bytes required
	if len(as_bytes) != 8 {
		return "", errors.New(fmt.Sprintf("Input string is incorrect for blowfish! Requires exactly of 8 characters, str = %s", str))
	}

	// 8-Byte Buffers:
	input := as_bytes
	output := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	// Create the blowfish cypher
	cypher, err := blowfish.NewCipher(blowfish_key)
	if nil != err {
		return "", err
	}

	// Encrypt the buffer
	cypher.Decrypt(output, input)

	// Remove the trailing 0x00 bytes we added to the string
	for i := 7; i >= 0 && output[i] == 0x00; i-- {
		output = output[0:i]
	}

	// Convert the byte array back to a string
	return strings.TrimSpace(string(output)), nil
}
