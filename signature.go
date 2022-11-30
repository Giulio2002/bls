package bls

import (
	"fmt"

	blst "github.com/supranational/blst/bindings/go"
)

// Length of a BLS signature
const signatureLength = 96

// ETH2 uses BLS12381-G2 Curve
var defaultCurve = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

// Signature wraps CGO object repressenting the signature.
type Signature struct {
	signature *blst.P2Affine
	buffer    []byte
	curve     []byte
}

// NewSignature creates a new empty signature.
func NewSignature() *Signature {
	return &Signature{
		signature: new(blst.P2Affine),
		buffer:    make([]byte, signatureLength),
		curve:     defaultCurve,
	}
}

// NewSignatureFromBytes creates a new signature from a 96 bytes long slice.
func NewSignatureFromBytes(b []byte) (*Signature, error) {
	if len(b) != signatureLength {
		return nil, fmt.Errorf("bls(signature): invalid signature length. should be %d", signatureLength)
	}
	signature := new(blst.P2Affine).Uncompress(b)
	if signature == nil {
		return nil, ErrDeserializePrivateKey
	}
	// Group check signature. Do not check for infinity since an aggregated signature
	// could be infinite.
	if !signature.SigValidate(false) {
		return nil, ErrNotGroupSignature
	}
	return &Signature{
		signature: signature,
		buffer:    copyBytes(b),
		curve:     defaultCurve,
	}, nil
}

// SetCurve change signature curve.
func (sig *Signature) SetCurve(curve []byte) {
	sig.curve = copyBytes(curve)
}

// Bytes returns bytes repressentation.
func (sig *Signature) Bytes(b []byte) []byte {
	return sig.buffer
}

// VerifyAggregate verify signature against many public keys.
func (sig *Signature) VerifyAggregate(msg []byte, publicKeys []*PublicKey) bool {
	affines := []*blst.P1Affine{}
	for _, publicKey := range publicKeys {
		affines = append(affines, publicKey.publicKey)
	}
	return sig.signature.FastAggregateVerify(true, affines, msg, sig.curve)
}

// Verify verify signature against one public key.
func (sig *Signature) Verify(msg []byte, pk *PublicKey) bool {
	return sig.signature.Verify(false, pk.publicKey, false, msg, sig.curve)
}

// VerifyAggregate verify signature against many public keys.
func VerifyAggregate(signature []byte, msg []byte, publicKeysBytes [][]byte) (bool, error) {
	sig, err := NewSignatureFromBytes(signature)
	if err != nil {
		return false, err
	}

	publicKeys := []*PublicKey{}
	for _, publicKey := range publicKeysBytes {
		key, err := NewPublicKeyFromBytes(publicKey)
		if err != nil {
			return false, err
		}
		publicKeys = append(publicKeys, key)
	}

	return sig.VerifyAggregate(msg, publicKeys), nil
}

// Verify verify signature against one public key.
func Verify(signature []byte, msg []byte, publicKeyBytes []byte) (bool, error) {
	sig, err := NewSignatureFromBytes(signature)
	if err != nil {
		return false, err
	}

	publicKey, err := NewPublicKeyFromBytes(publicKeyBytes)
	if err != nil {
		return false, err
	}

	return sig.Verify(msg, publicKey), nil
}
