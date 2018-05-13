package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

// ErrCipherMismatch Public error
var ErrCipherMismatch = errors.New("encrypt: cipher and authorization does not match.")
var ErrCipherTooShort = errors.New("encrypt: cipher too short")

func Encrypt(key []byte, value string) (cipherString, auth string, err error) {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	//key, _ := hex.DecodeString("6368616e676520746869732070617373")
	//plaintext := []byte("some plaintext")

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(value))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(value))

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	// CheckMAC reports whether messageMAC is a valid HMAC tag for message.

	mac := hmac.New(sha256.New, key)
	mac.Write(ciphertext)
	expectedMAC := mac.Sum(nil)

	auth = base64.URLEncoding.EncodeToString(expectedMAC)
	cipherString = base64.URLEncoding.EncodeToString(ciphertext)

	return cipherString, auth, nil
}

func Decrypt(key []byte, cipherString, auth string) (string, error) {

	cipherBytes, err := base64.URLEncoding.DecodeString(cipherString)
	if err != nil {
		return "", err
	}

	authBytes, err := base64.URLEncoding.DecodeString(auth)
	if err != nil {
		return "", err
	}

	// Verify the authentication string
	match := checkMAC(key, cipherBytes, authBytes)
	if !match {
		return "", ErrCipherMismatch
	}
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	//key, _ := hex.DecodeString("6368616e676520746869732070617373")
	//ciphertext, _ := hex.DecodeString("7dd015f06bec7f1b8f6559dad89f4131da62261786845100056b353194ad")

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(cipherBytes) < aes.BlockSize {
		return "", ErrCipherTooShort
	}
	iv := cipherBytes[:aes.BlockSize]
	cipherBytes = cipherBytes[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherBytes, cipherBytes)
	return string(cipherBytes), nil
}

func checkMAC(key, message, messageMAC []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}
