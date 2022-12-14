package bls

import (
	"errors"
)

var (
	// Private key errors
	ErrZeroPrivateKey        = errors.New("bls(private): zero key")
	ErrDeserializePrivateKey = errors.New("bls(private): could not deserialize")
	// Public key errors
	ErrDeserializePublicKey = errors.New("bls(public): could not deserialize")
	ErrInfinitePublicKey    = errors.New("bls(public): infinity")
	// Signature errors
	ErrDeserializeSignature = errors.New("bls(signature): could not deserialize")
	ErrNotGroupSignature    = errors.New("bls(signature): signature is not in group")
)
