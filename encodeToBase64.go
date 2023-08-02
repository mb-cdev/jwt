package jwt

import (
	"bytes"
	"encoding/base64"
)

func encodeToBase64(src []byte) []byte {
	buffer := bytes.NewBuffer([]byte{})
	enc := base64.NewEncoder(base64.RawURLEncoding, buffer)

	_, errEncoder := enc.Write(src)
	if errEncoder != nil {
		return nil
	}
	enc.Close()

	return buffer.Bytes()
}
