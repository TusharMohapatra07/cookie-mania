/*
	COOKIE READ WRITE WITH ENCRYPTION: This package provides functionality for secure cookie handling

with encryption using AES-GCM (Galois/Counter Mode).

The cookie value will be encrypted using AES-256-GCM which provides both confidentiality
and authenticity. GCM mode combines the counter mode of operation for encryption with
the Galois mode for authentication.

The final cookie value will be in the format of {NONCE}{CIPHERTEXT}{AUTH TAG}.
A random nonce is generated for each encryption operation to ensure uniqueness.
The authentication tag helps verify the integrity of the encrypted data.

Note: The encryption key should be kept secure and should have sufficient entropy
(32 bytes recommended for AES-256).
*/
package cookieerw

import (
	"cookieMania/cookierw"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"net/http"
)

func WriteEncrypted(w http.ResponseWriter, cookie http.Cookie, secretKey []byte) error {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return err
	}

	plainText := fmt.Sprintf("%s:%s", cookie.Name, cookie.Value)

	encryptedValue := aesGCM.Seal(nonce, nonce, []byte(plainText), nil)

	cookie.Value = string(encryptedValue)

	return cookierw.Write(w, cookie)
}
