# About pemutil [![Build Status](https://travis-ci.org/knq/pemutil.svg)](https://travis-ci.org/knq/pemutil) [![Coverage Status](https://coveralls.io/repos/knq/pemutil/badge.svg?branch=master&service=github)](https://coveralls.io/github/knq/pemutil?branch=master) #

A [Golang](https://golang.org/project) package that provides a light wrapper to
load PEM-encoded data, meant to ease the loading, parsing and decoding of PEM
data into standard [crypto](https://golang.org/pkg/crypto/) primitives.

## Installation ##

Install the package via the following:

    go get -u github.com/knq/pemutil

## Usage ##

Please see [the GoDoc API page](http://godoc.org/github.com/knq/pemutil) for a
full API listing.

The pemutil package can be used similarly to the following:

```go
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
```
