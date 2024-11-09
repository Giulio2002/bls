package bls

import (
	"bytes"
	"sync"

	blst "github.com/supranational/blst/bindings/go"
)

var (
	pkCache      *publicKeysCache
	enabledCache bool
)

// We build a basic cache to avoid allocs with sync.Map.
type kvCache struct {
	key   []byte
	value *blst.P1Affine
}

type publicKeysCache struct {
	cache [][]kvCache

	mu sync.RWMutex
}

const baseCacheLayer = 16384

// init is used to initialize cache
func init() {
	pkCache = &publicKeysCache{}
	pkCache.cache = make([][]kvCache, baseCacheLayer)
}

func SetEnabledCaching(caching bool) {
	enabledCache = caching
}

func ClearCache() {
	pkCache.cache = make([][]kvCache, baseCacheLayer)
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
	p.cache[key[0]] = append(p.cache[key[0]], kvCache{key: key, value: affine})
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
	p.mu.RLock()
	defer p.mu.RUnlock()
	var idx int
	for i := 0; i < publicKeyLength; i++ {
		idx += int(key[i])
	}

	candidates := p.cache[idx%baseCacheLayer]
	for _, candidate := range candidates {
		if bytes.Equal(candidate.key, key) {
			return candidate.value
		}
	}
	return nil
}
