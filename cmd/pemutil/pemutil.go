package main

// A simple command line util making to generate suitable keyset data for use
// with the pemutil package.

import (
	"crypto/elliptic"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/knq/pemutil"
)

var (
	flagAlg    = flag.String("t", "", "key type (sym, rsa, ecc)")
	flagKeyLen = flag.Int("l", 0, "key length for -t sym or -t rsa (512, 1024, 2048, 4096, ...)")
	flagCurve  = flag.String("c", "", "curve name for -t ecc (P224, P256, P384, P521)")
)

func main() {
	var keyset pemutil.Store
	var err error

	flag.Parse()

Generate:
	switch *flagAlg {
	case "sym":
		if *flagKeyLen == 0 {
			err = errors.New("must specify key length (-l)")
			break Generate
		}
		keyset, err = pemutil.GenerateSymmetricKeySet(*flagKeyLen)

	case "rsa":
		if *flagKeyLen == 0 {
			err = errors.New("must specify key length (-l)")
			break Generate
		}
		keyset, err = pemutil.GenerateRSAKeySet(*flagKeyLen)

	case "ecc":
		var curve elliptic.Curve
		switch strings.ToUpper(*flagCurve) {
		case "P224":
			curve = elliptic.P224()
		case "P256":
			curve = elliptic.P256()
		case "P384":
			curve = elliptic.P384()
		case "P521":
			curve = elliptic.P521()

		default:
			err = errors.New("unknown curve")
			break Generate
		}

		keyset, err = pemutil.GenerateECKeySet(curve)

	default:
		err = errors.New("unknown key type")
	}

	// check for errors
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}

	// encode pem data
	buf, err := keyset.Bytes()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// output
	_, err = os.Stdout.Write(buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
