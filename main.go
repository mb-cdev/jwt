package main

import (
	"fmt"

	"github.com/mb-cdev/jwt/jwt"
)

var secret = []byte{1, 2, 3, 4}

func main() {

	j := jwt.New(jwt.AlgoHS256, secret)
	j.SetPayload("test", 123.45)
	d := j.String()
	fmt.Println(d)
	c, _ := jwt.FromBytes([]byte(d), secret)
	i, e := c.GetFloat64("test")
	fmt.Println(i, e)
}
