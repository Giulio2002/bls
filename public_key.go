package bls

import (
	"fmt"

	blst "github.com/supranational/blst/bindings/go"
)

// Length of a BLS public key
const publicKeyLength = 48

// Helper method to help us make copy of buffers
func copyBytes(x []byte) (y []byte) {
	y = make([]byte, len(x))
	copy(y, x)
	return
}

// PublicKey wraps the CGO object of the BLST library and give us easy access to its methods.
type PublicKey struct {
	publicKey *blst.P1Affine
	buffer    []byte
}

// NewPublicKey makes new empty Public Key.
func NewPublicKey() *PublicKey {
	return &PublicKey{
		publicKey: new(blst.P1Affine),
		buffer:    make([]byte, publicKeyLength),
	}
}

// NewPublicKeyFromBytes Derive new public key from a 48 long byte slice.
func NewPublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != publicKeyLength {
		return nil, fmt.Errorf("bls(public): invalid key length. should be %d", publicKeyLength)
	}

	// Subgroup check NOT done when decompressing pubkey.
	p := new(blst.P1Affine).Uncompress(b)
	if p == nil {
		return nil, ErrDeserializePublicKey
	}
	// Subgroup and infinity check
	if !p.KeyValidate() {
		return nil, ErrInfinitePublicKey
	}

	return &PublicKey{
		publicKey: p,
		buffer:    copyBytes(b),
	}, nil
}

// Bytes returns the bytes repressentation of the public key.
func (pk *PublicKey) Bytes(b []byte) []byte {
	return pk.buffer
}
