// Package pemutil provides a simple, high-level API to load standard crypto
// primitives (ie, rsa.PrivateKey, ecdsa.PrivateKey, etc) from PEM data
// in-memory, on disk, etc.
package pemutil

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
)

// PEM is the set of PEM encoded data to be parsed and decoded. Each item in
// PEM must be a byte slice, an io.Reader, or a string (assumed to be a
// filename).
//
// Standard crypto primitives (ie, rsa.PrivateKey, etc)  can then be loaded
// into a Store via a call to PEM.Load(Store).
type PEM []interface{}

// BlockType is a PEM block type.
type BlockType string

// String satisfies the string interface for a block type.
func (bt BlockType) String() string {
	return string(bt)
}

const (
	// PrivateKey is the "PRIVATE KEY" block type.
	PrivateKey BlockType = "PRIVATE KEY"

	// PublicKey is the "PUBLIC KEY" block type.
	PublicKey BlockType = "PUBLIC KEY"

	// RSAPrivateKey is the "RSA PRIVATE KEY" block type.
	RSAPrivateKey BlockType = "RSA PRIVATE KEY"

	// ECPrivateKey is the "EC PRIVATE KEY" block type.
	ECPrivateKey BlockType = "EC PRIVATE KEY"

	// Certificate is the "CERTIFICATE" block type.
	Certificate BlockType = "CERTIFICATE"
)

// Store is a store for decoded PEM block types.
type Store map[BlockType]interface{}

// parsePKCSPrivateKey attempts to decode a RSA private key using first PKCS1
// encoding, and then PKCS8 encoding.
func parsePKCSPrivateKey(buf []byte) (interface{}, error) {
	// attempt PKCS1 parsing
	key, err := x509.ParsePKCS1PrivateKey(buf)
	if err != nil {
		// attempt PKCS8 parsing
		return x509.ParsePKCS8PrivateKey(buf)
	}

	return key, nil
}

// DecodePEM decodes the PEM data from buf, storing any resulting crypto
// primitives into the provided store using the PEM BlockType as the store map
// key.
func DecodePEM(store Store, buf []byte) error {
	var block *pem.Block

	// loop over blocks and parse the data, storing the resulting blocktype
	// after it has been decoded into the store
	for len(buf) > 0 {
		block, buf = pem.Decode(buf)
		if block == nil {
			return errors.New("invalid PEM data")
		}

		switch BlockType(block.Type) {
		// decode private key
		case PrivateKey:
			// try pkcs1 and pkcs8 decoding first
			key, err := parsePKCSPrivateKey(block.Bytes)
			if err != nil {
				// use the raw b64 decoded bytes
				key = block.Bytes
			}
			store[PrivateKey] = key

		// decode public key
		case PublicKey:
			// initial parse
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				// use the raw b64 decoded bytes
				key = block.Bytes
			}
			store[PublicKey] = key

		// decode rsa private key, attempting parsing using pkcs1, then pkcs8
		case RSAPrivateKey:
			key, err := parsePKCSPrivateKey(block.Bytes)
			if err != nil {
				return err
			}
			store[RSAPrivateKey] = key

		// decode ec private key
		case ECPrivateKey:
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return err
			}
			store[ECPrivateKey] = key

		// decode certificate
		case Certificate:
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return err
			}
			store[Certificate] = cert

		default:
			return fmt.Errorf("encountered unknown block type %s", block.Type)
		}
	}

	return nil
}

// Load inspects the types of each item in PEM, parsing and decoding the
// PEM-encoded data. Raw PEM data will be parsed and decoded from provided byte
// slices, and io.Reader's, and additionally, as a convenience,  any item of
// type string will be treated as a filename, from which the PEM data will be
// parsed and decoded.
//
// The resulting crypto primitives (ie, rsa.PrivateKey, etc) decoded from the
// PEM data will then be stored under its respective BlockType in the store,
// with the BlockType as the store's map key.
//
// Crypto primitives can then be retrieved from the store, and type asserted
// into the its expected type (ie, rsa.PrivateKey, ecdsa.PrivateKey, etc).
func (p PEM) Load(store map[BlockType]interface{}) error {
	var buf []byte
	var err error

	// loop over data and attempt decoding
	for i, c := range p {
		switch obj := c.(type) {
		// treat string as filename
		case string:
			buf, err = ioutil.ReadFile(obj)
			if err != nil {
				return err
			}

		// reader
		case io.Reader:
			buf, err = ioutil.ReadAll(obj)
			if err != nil {
				return err
			}

		// raw bytes
		case []byte:
			buf = obj

		default:
			return fmt.Errorf("encountered invalid type '%s' at position %d. PEM data must be of type string, io.Reader, or []byte", reflect.TypeOf(c), i)
		}

		// decode PEM into store
		err = DecodePEM(store, buf)
		if err != nil {
			return err
		}
	}

	return nil
}
