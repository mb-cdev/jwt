package jwt

import (
	"encoding/json"
)

type Jwt struct {
	algo    string
	header  map[string]any
	payload map[string]any
	secret  []byte
}

func New(algo string, secret []byte) *Jwt {
	return &Jwt{
		algo: algo,
		header: map[string]any{
			"typ": JWTHeaderTypValue,
			"alg": algo,
		},
		payload: map[string]any{},
		secret:  secret,
	}
}

func (j *Jwt) SetHeader(key string, value any) {
	j.header[key] = value
}

func (j *Jwt) SetPayload(key string, value any) {
	j.payload[key] = value
}

func (j *Jwt) Bytes() []byte {
	headerBytes, errHeader := json.Marshal(j.header)
	if errHeader != nil {
		return nil
	}
	payloadBytes, errPayload := json.Marshal(j.payload)
	if errPayload != nil {
		return nil
	}

	headerBytesB64 := encodeToBase64(headerBytes)
	payloadBytesB64 := encodeToBase64(payloadBytes)

	hashFunc, errHashFunc := getHashFunction(j.algo)
	if errHashFunc != nil {
		return nil
	}

	out := joinParts(headerBytesB64, payloadBytesB64)
	signature, errSignature := calculateSignature(
		hashFunc,
		j.secret,
		out,
	)

	if errSignature != nil {
		return nil
	}

	return joinParts(out, encodeToBase64(signature))
}

func (j *Jwt) String() string {
	return string(j.Bytes())
}
