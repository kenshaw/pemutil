// Command pemutil is a simple command line util making to generate suitable
// keyset data for use with the pemutil package.
package main

import (
	"crypto/elliptic"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kenshaw/pemutil"
)

func main() {
	flagAlg := flag.String("t", "", "key type (sym, rsa, ecc)")
	flagKeyLen := flag.Int("l", 0, "key length for -t sym or -t rsa (512, 1024, 2048, 4096, ...)")
	flagCurve := flag.String("c", "", "curve name for -t ecc (P224, P256, P384, P521)")
	flag.Parse()
	if err := run(*flagAlg, *flagKeyLen, *flagCurve); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(alg string, keyLen int, curveType string) error {
	if (alg == "sym" || alg == "rsa") && keyLen == 0 {
		return fmt.Errorf("must specify key length (-l) for %s key types", alg)
	}
	var curve elliptic.Curve
	if alg == "ecc" {
		switch strings.ToUpper(curveType) {
		case "P224":
			curve = elliptic.P224()
		case "P256":
			curve = elliptic.P256()
		case "P384":
			curve = elliptic.P384()
		case "P521":
			curve = elliptic.P521()
		default:
			return fmt.Errorf("unknown curve %q", curveType)
		}
	}
	var keyset pemutil.Store
	var err error
	switch alg {
	case "sym":
		keyset, err = pemutil.GenerateSymmetricKeySet(keyLen)
	case "rsa":
		keyset, err = pemutil.GenerateRSAKeySet(keyLen)
	case "ecc":
		keyset, err = pemutil.GenerateECKeySet(curve)
	default:
		return fmt.Errorf("unknown key type %q", alg)
	}
	if err != nil {
		return err
	}
	buf, err := keyset.Bytes()
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(buf)
	return err
}
