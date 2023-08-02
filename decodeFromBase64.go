package jwt

import (
	"bytes"
	"encoding/base64"
	"io"
)

func decodeFromBase64(data []byte) []byte {
	buffer := bytes.NewBuffer(data)
	dec := base64.NewDecoder(base64.RawURLEncoding, buffer)
	out, err := io.ReadAll(dec)
	if err != nil {
		return nil
	}

	return out
}
