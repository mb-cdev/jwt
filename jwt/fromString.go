package jwt

import (
	"bytes"
	"encoding/json"
	"errors"
)

var errWrongToken = errors.New("wrong JWT format")
var errWrongTyp = errors.New("wrong JWT typ")
var errWrongAlgo = errors.New("wrong JWT algo")

func FromBytes(data []byte, secret []byte) (*Jwt, error) {
	dataParts := bytes.Split(data, []byte{'.'})
	if len(dataParts) < 3 {
		return nil, errWrongToken
	}

	base64Header := dataParts[0]
	base64Payload := dataParts[1]

	header := decodeFromBase64(base64Header)
	payload := decodeFromBase64(base64Payload)

	headerMap := make(map[string]any, 2)
	errUnmarshall := json.Unmarshal(header, &headerMap)
	if errUnmarshall != nil {
		return nil, errUnmarshall
	}

	typ, okTyp := headerMap[JWTHeaderTypKey]
	if !okTyp || typ != JWTHeaderTypValue {
		return nil, errWrongTyp
	}

	algo, okAlgo := headerMap[JWTHeaderAlgKey]
	if !okAlgo {
		return nil, errWrongAlgo
	}

	algoString, okAlgoString := algo.(string)
	if !okAlgoString {
		return nil, errWrongAlgo
	}

	_, errHashFunction := getHashFunction(algoString)
	if errHashFunction != nil {
		return nil, errHashFunction
	}

	j := New(algoString, secret)
	j.header = headerMap
	json.Unmarshal(payload, &j.payload)

	return j, nil
}
