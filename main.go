package main

import (
	"encoding/hex"
	"fmt"

	"github.com/jofwar/gophercises-secret/encrypt"
)

func main() {
	key, _ := hex.DecodeString("6368616e676520746869732070617373")
	cipher, auth, err := encrypt.Encrypt(key, "Jason rocks!")
	if err != nil {
		panic(err)
	}

	fmt.Println("Cipher:", cipher)
	fmt.Println("Auth:", auth)

	plain, err := encrypt.Decrypt(key, cipher, auth)
	if err != nil {
		panic(err)
	}

	fmt.Println("Plain:", plain)
}
