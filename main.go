package main

import (
	"fmt"

	"github.com/mb-cdev/jwt/jwt"
)

var secret = []byte{1, 2, 3, 4}

func main() {

	j := jwt.New(jwt.AlgoHS256, secret)

	j.SetPayload("test", 1)
	j.SetPayload("test1", 2)
	j.SetPayload("asd2", map[string]any{
		"test": 2,
		"asd":  333,
	})

	d := j.String()

	fmt.Println(d)
	c, err := jwt.FromBytes([]byte(d), secret)

	fmt.Println(c, err)
}
