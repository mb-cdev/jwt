package jwt

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
)

func decodeFromBase64(data []byte) []byte {
	buffer := bytes.NewBuffer(data)
	dec := base64.NewDecoder(base64.RawURLEncoding, buffer)
	out, err := ioutil.ReadAll(dec)
	if err != nil {
		return nil
	}

	return out
}
