package jwt

import (
	"encoding/json"
	"errors"
	"strconv"
)

var errKeyNotFoundInPayload = errors.New("key not found in payload")
var errWrongType = errors.New("wrong type")

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

// region setters

func (j *Jwt) SetHeader(key string, value any) {
	j.header[key] = value
}

func (j *Jwt) SetPayload(key string, value any) {
	j.payload[key] = value
}

//endregion setters

//region getters

func (j *Jwt) Get(key string) (any, error) {
	val, ok := j.payload[key]
	if !ok {
		return nil, errKeyNotFoundInPayload
	}
	return val, nil
}

func (j *Jwt) GetString(key string) (string, error) {
	val, err := j.Get(key)
	if err != nil {
		return "", err
	}

	valString, valStringOk := val.(string)
	if !valStringOk {
		return "", errWrongType
	}

	return valString, nil
}

func (j *Jwt) GetFloat64(key string) (float64, error) {
	val, err := j.Get(key)
	if err != nil {
		return 0, err
	}

	valFloat, valFloatOk := val.(float64)
	if !valFloatOk {
		valString, valStringOk := val.(string)
		if !valStringOk {
			return 0, errWrongType
		}

		valFloat, err = strconv.ParseFloat(valString, 64)
		if err != nil {
			return 0, errWrongType
		}
	}

	return valFloat, nil
}

//endregion getters

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
