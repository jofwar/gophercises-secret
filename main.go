package main

import (
	"encoding/hex"
	"fmt"

	"github.com/jofwar/gophercises-secret/encrypt"
)

func main() {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")

	fmt.Println(encrypt.Encrypt(key, "some-value"))
}
