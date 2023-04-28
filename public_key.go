package bls

import (
	"errors"
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

	cacheKey := convertRawPublickKeyToCacheKey(b)
	cachedAffine := getAffineFromCache(cacheKey)
	if cachedAffine != nil {
		return &PublicKey{
			publicKey: cachedAffine,
			buffer:    copyBytes(b),
		}, nil
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
	loadAffineIntoCache(cacheKey, p)

	return &PublicKey{
		publicKey: p,
		buffer:    copyBytes(b),
	}, nil
}

func newPublicKeyFromAffine(affine *blst.P1Affine) *PublicKey {
	return &PublicKey{
		publicKey: affine,
		buffer:    copyBytes(affine.Compress()),
	}
}

// Bytes returns the bytes repressentation of the public key.
func (pk *PublicKey) Bytes(b []byte) []byte {
	return pk.buffer
}

func AggregatePublickKeys(pubs [][]byte) ([]byte, error) {
	if len(pubs) == 0 {
		return nil, errors.New("nil or empty public keys")
	}
	agg := new(blst.P1Aggregate)
	mulP1 := make([]*blst.P1Affine, 0, len(pubs))
	for _, pubkey := range pubs {
		pubKeyObj, err := NewPublicKeyFromBytes(pubkey)
		if err != nil {
			return nil, err
		}
		mulP1 = append(mulP1, pubKeyObj.publicKey)
	}
	// No group check needed here since it is done in PublicKeyFromBytes
	// Note the checks could be moved from PublicKeyFromBytes into Aggregate
	// and take advantage of multi-threading.
	agg.Aggregate(mulP1, false)
	return copyBytes(agg.ToAffine().Compress()), nil
}
