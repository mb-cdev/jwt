package jwt

import (
	"bytes"
	"encoding/json"
)

func IsTokenValidFromString(algo string, base64Token string, secret []byte) (bool, error) {
	return IsTokenValid(algo, []byte(base64Token), secret)
}

func IsTokenValid(algo string, base64Token []byte, secret []byte) (bool, error) {
	parts := bytes.Split(base64Token, []byte{'.'})
	if len(parts) < 3 {
		return false, ErrBadSignature
	}

	signature := decodeFromBase64(parts[2])
	return isSignatureValid(algo, parts[0], parts[1], signature, secret)
}

func isSignatureValid(algo string, base64Header, base64Payload, signature []byte, secret []byte) (bool, error) {
	if algo == "" {
		algo = getAlgoFromHeader(base64Header)
	}

	hashFunc, errHashFunction := getHashFunction(algo)
	if errHashFunction != nil {
		return false, errHashFunction
	}

	signatureRecalculated, errSignatureRecalculated := calculateSignature(
		hashFunc, secret, joinParts(base64Header, base64Payload),
	)
	if errSignatureRecalculated != nil {
		return false, errSignatureRecalculated
	}

	if !bytes.Equal(signature, signatureRecalculated) {
		return false, ErrBadSignature
	}

	return true, nil
}

func getAlgoFromHeader(base64Header []byte) string {
	header := decodeFromBase64(base64Header)

	headerMap := make(map[string]any, 2)
	json.Unmarshal(header, &headerMap)

	algo, algoOk := headerMap[JWTHeaderAlgKey]
	if !algoOk {
		return ""
	}

	algoString, algoStringOk := algo.(string)
	if !algoStringOk {
		return ""
	}

	return algoString
}
