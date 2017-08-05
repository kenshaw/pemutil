// example/example.go
package main

//go:generate openssl genrsa -out rsa-private.pem 2048
//go:generate openssl rsa -in rsa-private.pem -outform PEM -pubout -out rsa-public.pem

import (
	"log"
	"os"

	"github.com/knq/pemutil"
)

func main() {
	var err error

	// create store and load our private key
	s := pemutil.Store{}
	err = s.LoadFile("rsa-private.pem")
	if err != nil {
		log.Fatal(err)
	}

	// ensure that the corresponding public key exists
	err = s.AddPublicKeys()
	if err != nil {
		log.Fatal(err)
	}

	// do something with s[pemutil.RSAPrivateKey]

	// get pem data
	buf, err := s.Bytes()
	if err != nil {
		log.Fatal(err)
	}
	os.Stdout.Write(buf)
}
