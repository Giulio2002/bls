package bls

import (
	"sync"
	"unsafe"

	blst "github.com/supranational/blst/bindings/go"
)

var (
	pkCache      *publicKeysCache
	enabledCache bool
)

type publicKeysCache struct {
	publicKeyCache sync.Map
}

// init is used to initialize cache
func init() {
	pkCache = &publicKeysCache{}
}

func SetEnabledCaching(caching bool) {
	enabledCache = caching
}

func ClearCache() {
	pkCache.publicKeyCache.Clear()
}

func (p *publicKeysCache) loadPublicKeyIntoCache(publicKey []byte, validate bool) error {
	if len(publicKey) != publicKeyLength {
		return ErrDeserializePublicKey
	}
	if affine := p.getAffineFromCache(publicKey); affine != nil {
		return nil
	}
	// Subgroup check NOT done when decompressing pubkey.
	publicKeyDecompressed := new(blst.P1Affine).Uncompress(publicKey)
	if p == nil {
		return ErrDeserializePublicKey
	}
	// Subgroup and infinity check
	if validate && !publicKeyDecompressed.KeyValidate() {
		return ErrInfinitePublicKey
	}
	p.loadAffineIntoCache(publicKey, publicKeyDecompressed)
	return nil
}

func (p *publicKeysCache) loadAffineIntoCache(key []byte, affine *blst.P1Affine) {
	if !enabledCache {
		return
	}
	p.publicKeyCache.Store((*[48]byte)(unsafe.Pointer(&key[0])), *affine)
}

func LoadPublicKeyIntoCache(publicKey []byte, validate bool) error {
	if !enabledCache {
		return ErrCacheNotEnabled
	}
	return pkCache.loadPublicKeyIntoCache(publicKey, validate)
}

func (p *publicKeysCache) getAffineFromCache(key []byte) *blst.P1Affine {
	if !enabledCache {
		return nil
	}
	if len(key) != publicKeyLength {
		return nil
	}
	val, ok := p.publicKeyCache.Load((*[48]byte)(unsafe.Pointer(&key[0])))
	if !ok {
		return nil
	}

	// let's not check if this succeeds, as it must.
	affine, _ := val.(blst.P1Affine)
	return &affine
}
