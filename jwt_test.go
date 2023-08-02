package jwt_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mb-cdev/jwt"
)

func TestJwtSignature(t *testing.T) {
	testingTable := []struct {
		testId        string
		algo          string
		payload       map[string]any
		secret        []byte
		expectedToken string
	}{
		{
			testId:        "tokenTest#1",
			algo:          jwt.AlgoHS256,
			payload:       map[string]any{"key1": 123, "key2": "test123"},
			secret:        []byte{1, 2, 3, 4, 5, 6, 7},
			expectedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJrZXkxIjoxMjMsImtleTIiOiJ0ZXN0MTIzIn0.Gr3aT4thU9ThW-udCxIRyUnMSaU1CwCCjdEFQqX-m-4",
		},
		{
			testId:        "tokenTest#2",
			algo:          jwt.AlgoHS512,
			payload:       map[string]any{"key1": 123, "key2": "test123"},
			secret:        []byte{1, 2, 3, 4, 5, 6, 7},
			expectedToken: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJrZXkxIjoxMjMsImtleTIiOiJ0ZXN0MTIzIn0.x0m_mSAWEp3jNQjPC9Gt1Mns3NUekEt5s3Vsg5s1uuIiPjS9oVkPJTmVr6hChCFZP5k-6iVNdWtoMjXAUp9SUQ",
		},
		{
			testId:        "tokenTest#3",
			algo:          jwt.AlgoHS512,
			payload:       map[string]any{"key2": "test123"},
			secret:        []byte{7, 6, 5, 4, 3, 2, 1},
			expectedToken: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJrZXkyIjoidGVzdDEyMyJ9.4WRMmmBUZlBjlY38m7eyiIt35chbxln_o_TDgKfFCjZ4iRADNDqGuUwbfDn-HZhZU6D7OWuzxFowm-KjBhO-Vw",
		},
		{
			testId:        "tokenTest#4",
			algo:          jwt.AlgoHS512,
			payload:       map[string]any{},
			secret:        []byte{7, 6, 5, 4, 3, 2, 1},
			expectedToken: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.e30.pupOk_kKR3k1O2e--olG3Alfiteq6Usu03RHGa2-RVRO5_qsCkltpr3htotv0q4N3IY7MTywEeE0zjXp2_UGCA",
		},
		{
			testId:        "tokenTest#5",
			algo:          jwt.AlgoHS256,
			payload:       map[string]any{},
			secret:        []byte{1, 2, 3, 4, 5, 6, 7},
			expectedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.dNytVsNoufC7XNn3CXbkdorOqGwfCv2MfPVIcRJykFk",
		},
	}

	for _, testCase := range testingTable {
		//create new instance
		j := jwt.New(testCase.algo, testCase.secret)

		//set payload
		for key, value := range testCase.payload {
			j.SetPayload(key, value)
		}

		jwtToken := j.String()
		if strings.Compare(testCase.expectedToken, jwtToken) != 0 {
			t.Errorf("%s: wrong token; expected %s, got %s", testCase.testId, testCase.expectedToken, jwtToken)
		}
	}
}

func TestSamePayloadHeaderAndSecretDifferentHashFunction(t *testing.T) {
	secret := []byte{1, 2, 3, 4}

	j1 := jwt.New(jwt.AlgoHS512, secret)
	j2 := jwt.New(jwt.AlgoHS256, secret)

	j1.SetPayload("test", 1)
	j2.SetPayload("test", 1)

	if bytes.Equal(j1.Bytes(), j2.Bytes()) {
		t.Error("tokens are equal")
	}
}

func TestSamePayloadHeaderAndHashFunctionDifferentSecret(t *testing.T) {
	secret1 := []byte{1, 2, 3, 4}
	secret2 := []byte{4, 3, 2, 1}

	j1 := jwt.New(jwt.AlgoHS512, secret1)
	j2 := jwt.New(jwt.AlgoHS512, secret2)

	j1.SetPayload("test", 1)
	j2.SetPayload("test", 1)

	if bytes.Equal(j1.Bytes(), j2.Bytes()) {
		t.Error("tokens are equal")
	}
}