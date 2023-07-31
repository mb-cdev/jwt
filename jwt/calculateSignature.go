package jwt

import (
	"crypto/hmac"
	"hash"
)

// calculateSignature - calculate signature from base64Data := base64urlencode(header).base64urlencode(payload)
func calculateSignature(f func() hash.Hash, secret []byte, base64Data []byte) ([]byte, error) {
	h := hmac.New(f, secret)
	_, err := h.Write(base64Data)

	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
