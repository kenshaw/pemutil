// _example/main.go
package main

//go:generate openssl genrsa -out rsa-private.pem 2048
//go:generate openssl rsa -in rsa-private.pem -outform PEM -pubout -out rsa-public.pem

import (
	"log"
	"os"

	"github.com/kenshaw/pemutil"
)

func main() {
	// create store and load our private key
	keyset, err := pemutil.LoadFile("rsa-private.pem")
	if err != nil {
		log.Fatal(err)
	}

	// do something with keyset.RSAPrivateKey()

	// get pem data and write to disk
	buf, err := keyset.Bytes()
	if err != nil {
		log.Fatal(err)
	}
	os.Stdout.Write(buf)
}
