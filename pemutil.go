// Package pemutil provides various utility methods to assist in the decoding
// of PEM data into its constituent parts via a simple, high-level API.
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

// PEM is a set of PEM encoded data, of bytes ([]byte), io.Reader's or
// filenames.
//
// After instantiating this, objects
type PEM []interface{}

// BlockType is a PEM block type.
type BlockType string

// String satisfies the string interface.
func (bt BlockType) String() string {
	return string(bt)
}

// Store is a store for decoded PEM block types.
type Store map[BlockType]interface{}

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

// parsePKCSPrivateKey attempts to decode a RSA private key using first PKCS1
// encoding, and then PKCS8 encoding.
func parsePKCSPrivateKey(buf []byte) (interface{}, error) {
	var key interface{}

	// attempt PKCS1 parsing
	key, err := x509.ParsePKCS1PrivateKey(buf)
	if err != nil {
		// if there was a failure, then attempt PKCS8
		return x509.ParsePKCS8PrivateKey(buf)
	}

	return key, nil
}

// DecodePEM decodes the PEM data from buf into the provided store.
func DecodePEM(store map[BlockType]interface{}, buf []byte) error {
	var block *pem.Block

	// loop over blocks and parse the data, storing the resulting blocktype
	// after it has been decoded into the store
	for len(buf) > 0 {
		block, buf = pem.Decode(buf)
		if block == nil {
			return errors.New("invalid PEM data")
		}

		switch BlockType(block.Type) {
		case PrivateKey:
			var key interface{}

			// try pkcs1 and pkcs8 decoding first (ie, mislabeled RSA key)
			key, err := parsePKCSPrivateKey(block.Bytes)
			if err != nil {
				// use raw bytes
				key = block.Bytes
			}
			store[PrivateKey] = key

		// base64 decode public key
		case PublicKey:
			var key interface{}

			// do initial parse
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				// use raw bytes
				key = block.Bytes
			}
			store[PublicKey] = key

		// parse rsa private key using pkcs1 and then pkcs8
		case RSAPrivateKey:
			key, err := parsePKCSPrivateKey(block.Bytes)
			if err != nil {
				return err
			}
			store[RSAPrivateKey] = key

		// parse ec private key using x509
		case ECPrivateKey:
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return err
			}
			store[ECPrivateKey] = key

		// parse with x509
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

// Load reads the data from PEM and loads them into store, if possible. If an
// error is encountered, then it will be returned.
//
// Allowed PEM types can be raw PEM data ([]byte, or io.Reader) or a filename.
func (p PEM) Load(store map[BlockType]interface{}) error {
	var buf []byte
	var err error

	// loop over data and attempt decoding
	for i, c := range p {
		switch obj := c.(type) {
		case string: // assume filename
			buf, err = ioutil.ReadFile(obj)
			if err != nil {
				return err
			}

		case []byte: // raw pem data
			buf = obj

		case io.Reader: // reader
			buf, err = ioutil.ReadAll(obj)
			if err != nil {
				return err
			}

		default:
			return fmt.Errorf("Load encountered invalid type %s at position %d. PEM data must be of type string, []byte, or io.Reader", reflect.TypeOf(c), i)
		}

		// load the PEM into the store
		err = DecodePEM(store, buf)
		if err != nil {
			return err
		}
	}

	return nil
}
