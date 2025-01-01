// Package cookierw provides functions for reading and writing HTTP cookies with base64 encoding.
//
// When writing cookies, the value is automatically base64 encoded to ensure it only contains
// valid ASCII characters and meets HTTP cookie specifications. When reading cookies, the
// value is automatically decoded from base64.
//
// This package handles:
// - Base64 encoding/decoding of cookie values
// - Validation of cookie size limits
// - Safe reading and writing of cookie data

package cookierw

import (
	"encoding/base64"
	"errors"
	"net/http"
)

var (
	ErrValueTooLong = errors.New("cookie value too long")
	ErrInvalidValue = errors.New("invalid cookie value")
)

func Write(w http.ResponseWriter, cookie http.Cookie) error {
	cookie.Value = base64.URLEncoding.EncodeToString([]byte(cookie.Value))

	if len(cookie.String()) > 4096 {
		return ErrValueTooLong
	}

	http.SetCookie(w, &cookie)

	return nil
}

func Read(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", nil
	}

	value, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", ErrInvalidValue
	}

	return string(value), nil
}
