package cookiesrw

import (
	"crypto/hmac"
	"crypto/sha256"
	"net/http"

	"cookieMania/cookierw"
)

//COOKIE READ WRITE WITH SIGN: This adds a layer of verification by adding a signature.
//The cookie value will be of the form {HMAC SIGNATURE}{VALUE}. The signature will be
// generated using any hashing algorithm (sha256 in this package). The secret key used
// to generate the hash should not be shared anywhere. It should preferably be random
// hex string with higher bytes of entropy

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
