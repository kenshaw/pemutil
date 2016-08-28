// Package pemutil provides a simple, high-level API to load, parse, and decode
// standard crypto primitives (ie, rsa.PrivateKey, ecdsa.PrivateKey, etc) from
// PEM-encoded data.
//
// The pemutil package commonly used similar to the following:
//
//		store := pemutil.Store{}
//		pemutil.PEM{"myrsakey.pem"}.Load(store)
//
//		if rsaPrivKey, ok := store[pemutil.RSAPrivateKey].(*rsa.PrivateKey); !ok {
//			// do some kind of error
//		}
//
package pemutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
)

// PEM is a set of PEM-encoded data. Each item in PEM must be a byte slice, an
// io.Reader, or a string (strings are assumed to be a filename).
//
// Standard crypto primitives can then be loaded into a Store via a call to
// Load.
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

// Store is a store containing crypto primitives.
//
// A store can contain any of the following crypto primitives:
//     []byte 								-- raw key
//     *rsa.PrivateKey, *ecdsa.PrivateKey   -- private key
//     *rsa.PublicKey, *ecdsa.PublicKey     -- public key
type Store map[BlockType]interface{}

// EncodePrimitive encodes the crypto primitive obj into PEM-encoded data.
func EncodePrimitive(obj interface{}) ([]byte, error) {
	var err error
	var blockType BlockType
	var buf []byte

	switch v := obj.(type) {
	case []byte:
		blockType = PrivateKey
		buf = v

	case *rsa.PrivateKey:
		blockType = RSAPrivateKey
		buf = x509.MarshalPKCS1PrivateKey(v)

	case *ecdsa.PrivateKey:
		blockType = ECPrivateKey
		buf, err = x509.MarshalECPrivateKey(v)
		if err != nil {
			return nil, err
		}

	case *rsa.PublicKey, *ecdsa.PublicKey:
		blockType = PublicKey
		buf, err = x509.MarshalPKIXPublicKey(v)
		if err != nil {
			return nil, err
		}

	default:
		return nil, errors.New("EncodePrimitive: unsupported crypto primitive")
	}

	// encode and add to buffer
	pemBuf := pem.EncodeToMemory(&pem.Block{
		Type:  blockType.String(),
		Bytes: buf,
	})

	return pemBuf, nil
}

// Bytes returns all crypto primitives in the store as a single byte slice
// containing the PEM-encoded versions of the crypto primitives.
func (s Store) Bytes() ([]byte, error) {
	var res bytes.Buffer

	// loop over all primitives and add to res
	for _, p := range s {
		// encode primitive
		buf, err := EncodePrimitive(p)
		if err != nil {
			return nil, err
		}

		// add to buf
		_, err = res.Write(buf)
		if err != nil {
			return nil, err
		}
	}

	return res.Bytes(), nil
}

// parsePKCSPrivateKey attempts to decode a RSA private key first using PKCS1
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

// DecodePEM parses and decodes PEM-encoded data from buf, storing any
// resulting crypto primitives into the provided store. The associated PEM
// BlockType will be used as the store's map key for the crypto primitives.
func DecodePEM(store Store, buf []byte) error {
	var block *pem.Block

	// loop over blocks and parse the data, storing the decoded primitives
	for len(buf) > 0 {
		block, buf = pem.Decode(buf)
		if block == nil {
			return errors.New("DecodePEM: invalid PEM data")
		}

		switch BlockType(block.Type) {
		// decode private key
		case PrivateKey:
			// try pkcs1 and pkcs8 decoding
			key, err := parsePKCSPrivateKey(block.Bytes)
			if err == nil {
				// rsa decoding was successful
				store[RSAPrivateKey] = key
			} else {
				// otherwise just use the raw bytes (ie, the decoded b64 value)
				store[PrivateKey] = block.Bytes
			}

		// decode public key
		case PublicKey:
			// initial parse
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				// use the raw b64 decoded bytes
				key = block.Bytes
			}
			store[PublicKey] = key

		// decode rsa private key
		case RSAPrivateKey:
			// try pkcs1 then pkcs8 decoding
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
			return fmt.Errorf("DecodePEM: encountered unknown block type %s", block.Type)
		}
	}

	return nil
}

// Load inspects the types of each item in PEM, parsing and decoding the
// PEM-encoded data. Raw PEM data will be parsed and decoded from provided byte
// slices, and io.Reader's, and additionally, as a convenience, any item of
// type string will be treated as a filename, from which the PEM data will be
// parsed and decoded.
//
// The resulting crypto primitives (ie, rsa.PrivateKey, ecdsa.PrivateKey, etc)
// decoded from the PEM data will then be stored under its respective BlockType
// in the store, with the BlockType as the store's map key.
//
// Crypto primitives can then be retrieved from the store, and type asserted
// into the its expected type:
//
//		store := pemutil.Store{}
//		pemutil.PEM{"myrsakey.pem"}.Load(store)
//
//		if rsaPrivKey, ok := store[pemutil.RSAPrivateKey].(*rsa.PrivateKey); !ok {
//			// do some kind of error
//		}
//
func (p PEM) Load(store Store) error {
	var buf []byte
	var err error

	// loop over data and attempt decoding
	for _, c := range p {
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
			return fmt.Errorf("Load: unrecognized type %s", reflect.TypeOf(c))
		}

		// decode PEM into store
		err = DecodePEM(store, buf)
		if err != nil {
			return err
		}
	}

	return nil
}

// GenerateSymmetricKeySet generates a private key crypto primitive, returning
// it as a Store.
func GenerateSymmetricKeySet(len int) (Store, error) {
	// generate random bytes
	buf := make([]byte, len)
	c, err := rand.Read(buf)
	if err != nil {
		return nil, err
	} else if c != len {
		return nil, fmt.Errorf("could not generate %d random key bits", len)
	}

	store := make(Store)
	store[PrivateKey] = buf
	return store, nil
}

// GenerateRSAKeySet generates a RSA private and public key crypto primitives,
// returning them as a Store.
func GenerateRSAKeySet(bitLen int) (Store, error) {
	key, err := rsa.GenerateKey(rand.Reader, bitLen)
	if err != nil {
		return nil, err
	}

	store := make(Store)
	store[RSAPrivateKey] = key
	store[PublicKey] = key.Public()
	return store, nil
}

// GenerateECKeySet generates a EC private and public key crypto primitives,
// returning them as a Store.
func GenerateECKeySet(curve elliptic.Curve) (Store, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	store := make(Store)
	store[ECPrivateKey] = key
	store[PublicKey] = key.Public()
	return store, nil
}

// GeneratePublicKeys checks if a ECPrivateKey or RSAPrivateKey is present, and
// generates and stores the corresponding PublicKey block type.
func GeneratePublicKeys(store Store) error {
	// generate rsa public key
	if key, ok := store[RSAPrivateKey]; ok {
		rsaPrivKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return errors.New("GeneratePublicKeys: expected RSAPrivateKey to be *rsa.PrivateKey")
		}
		store[PublicKey] = rsaPrivKey.Public()
	}

	// generate ecdsa public key
	if key, ok := store[ECPrivateKey]; ok {
		ecdsaPrivKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("GeneratePublicKeys: expected ECPrivateKey to be *ecdsa.PrivateKey")
		}
		store[PublicKey] = ecdsaPrivKey.Public()
	}

	return nil
}
