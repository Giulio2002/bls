package bls

import (
	"sync"

	blst "github.com/supranational/blst/bindings/go"
)

var (
	pkCache      *publicKeysCache
	enabledCache bool
)

type publicKeysCache struct {
	publicKeyCache        map[[48]byte]blst.P1Affine
	publicKeySharedBuffer [48]byte
	mu                    sync.Mutex
}

// init is used to initialize cache
func init() {
	pkCache = &publicKeysCache{
		publicKeyCache: make(map[[48]byte]blst.P1Affine),
	}
}

func SetEnabledCaching(caching bool) {
	enabledCache = caching
}

func ClearCache() {
	pkCache.publicKeyCache = make(map[[48]byte]blst.P1Affine)
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
	p.mu.Lock()
	defer p.mu.Unlock()
	copy(p.publicKeySharedBuffer[:], key)
	p.publicKeyCache[p.publicKeySharedBuffer] = *affine
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
	p.mu.Lock()
	defer p.mu.Unlock()
	copy(p.publicKeySharedBuffer[:], key)
	affine, ok := p.publicKeyCache[p.publicKeySharedBuffer]
	if !ok {
		return nil
	}
	return &affine
}
