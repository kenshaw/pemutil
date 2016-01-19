// example/example.go
package main

//go:generate openssl genrsa -out rsa-private.pem 2048
//go:generate openssl rsa -in rsa-private.pem -outform PEM -pubout -out rsa-public.pem

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
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

	// encode key and pub key
	keyBuf := x509.MarshalPKCS1PrivateKey(key)
	pubKeyBuf, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		log.Fatalln(err)
	}

	// encode the data back into
	fmt.Printf("%s%s",
		pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBuf,
		}),
		pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBuf,
		}),
	)
}
