package jwt

import "bytes"

func joinParts(parts ...[]byte) []byte {
	return bytes.Join(parts, []byte{'.'})
}
