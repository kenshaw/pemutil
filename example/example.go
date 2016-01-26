// example/example.go
package main

//go:generate openssl genrsa -out rsa-private.pem 2048
//go:generate openssl rsa -in rsa-private.pem -outform PEM -pubout -out rsa-public.pem

import (
	"crypto/rsa"
	"log"
	"os"
	"reflect"

	"github.com/knq/pemutil"
)

func main() {
	store := pemutil.Store{}
	pemutil.PEM{"rsa-public.pem", "rsa-private.pem"}.Load(store)

	var ok bool
	var key *rsa.PrivateKey
	var pubKey *rsa.PublicKey

	if key, ok = store[pemutil.RSAPrivateKey].(*rsa.PrivateKey); !ok {
		log.Fatalln("key should be a *rsa.PrivateKey")
	}

	if pubKey, ok = store[pemutil.PublicKey].(*rsa.PublicKey); !ok {
		log.Fatalln("public key should be *rsa.PublicKey")
	}

	if !reflect.DeepEqual(pubKey, &key.PublicKey) {
		log.Fatalln("generated key and public key don't match")
	}

	// get pem data
	pemBuf, err := store.Bytes()
	if err != nil {
		log.Fatalln(err)
	}

	os.Stdout.Write(pemBuf)
}
