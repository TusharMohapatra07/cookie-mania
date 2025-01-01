// Package cookiesrw provides secure cookie handling with HMAC signature verification.
//
// The package implements signed cookie read/write operations where each cookie value
// is structured as: {HMAC-SHA256-Signature}{Original-Value}
//
// Key features:
// - Uses HMAC-SHA256 for cryptographic signing
// - Prevents cookie tampering via signature verification
// - Supports both reading and writing of signed cookies
//
// Security notes:
// - The secret key must be kept private and secure
// - Recommended to use high-entropy random keys (32+ bytes)
// - Do not reuse secret keys across different applications

package cookiesrw

import (
	"crypto/hmac"
	"crypto/sha256"
	"net/http"

	"cookieMania/cookierw"
)

func WriteSigned(w http.ResponseWriter, cookie http.Cookie, secretKey []byte) error {
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(cookie.Name))
	mac.Write([]byte(cookie.Value))
	signature := mac.Sum(nil)

	cookie.Value = string(signature) + cookie.Value

	return cookierw.Write(w, cookie)
}

func ReadSigned(r *http.Request, name string, secretKey []byte) (string, error) {
	signedValue, err := cookierw.Read(r, name)
	if err != nil {
		return "", nil
	}

	if len(signedValue) < sha256.Size {
		return "", cookierw.ErrInvalidValue
	}

	signature := signedValue[:sha256.Size]
	value := signedValue[sha256.Size:]

	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(name))
	mac.Write([]byte(value))
	expectedSignature := mac.Sum(nil)

	if !hmac.Equal(expectedSignature, []byte(signature)) {
		return "", cookierw.ErrInvalidValue
	}

	return value, nil
}
