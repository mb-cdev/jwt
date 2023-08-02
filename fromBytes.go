package jwt

import (
	"bytes"
	"encoding/json"
	"errors"
)

var ErrWrongToken = errors.New("wrong JWT format")
var ErrWrongTyp = errors.New("wrong JWT typ")
var ErrWrongAlgo = errors.New("wrong JWT algo")
var ErrBadSignature = errors.New("bad signature")

func FromBytes(data []byte, secret []byte) (*Jwt, error) {
	dataParts := bytes.Split(data, []byte{'.'})
	if len(dataParts) < 3 {
		return nil, ErrWrongToken
	}

	base64Header := dataParts[0]
	base64Payload := dataParts[1]
	base64Signature := dataParts[2]

	header := decodeFromBase64(base64Header)
	payload := decodeFromBase64(base64Payload)
	signature := decodeFromBase64(base64Signature)

	headerMap := make(map[string]any, 2)
	errUnmarshall := json.Unmarshal(header, &headerMap)
	if errUnmarshall != nil {
		return nil, errUnmarshall
	}

	typ, okTyp := headerMap[JWTHeaderTypKey]
	if !okTyp || typ != JWTHeaderTypValue {
		return nil, ErrWrongTyp
	}

	algo, okAlgo := headerMap[JWTHeaderAlgKey]
	if !okAlgo {
		return nil, ErrWrongAlgo
	}

	algoString, okAlgoString := algo.(string)
	if !okAlgoString {
		return nil, ErrWrongAlgo
	}

	hashFunc, errHashFunction := getHashFunction(algoString)
	if errHashFunction != nil {
		return nil, errHashFunction
	}

	signatureRecalculated, errSignatureRecalculated := calculateSignature(
		hashFunc, secret, joinParts(base64Header, base64Payload),
	)
	if errSignatureRecalculated != nil {
		return nil, errSignatureRecalculated
	}

	if !bytes.Equal(signature, signatureRecalculated) {
		return nil, ErrBadSignature
	}

	j := New(algoString, secret)
	j.header = headerMap
	json.Unmarshal(payload, &j.payload)

	return j, nil
}
