package jwt

func FromString(data string, secret []byte) (*Jwt, error) {
	return FromBytes([]byte(data), secret)
}
