package jwt

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
)

var errUnknownHashAlgo = errors.New("unknown hash algo")

const AlgoHS512 string = "HS512"
const AlgoHS256 string = "HS256"

var hashAlgoFuncs = map[string]func() hash.Hash{
	AlgoHS512: sha512.New,
	AlgoHS256: sha256.New,
}

func getHashFunction(algo string) (func() hash.Hash, error) {
	f, ok := hashAlgoFuncs[algo]
	if !ok {
		return nil, errUnknownHashAlgo
	}

	return f, nil
}
