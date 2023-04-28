package bls

import blst "github.com/supranational/blst/bindings/go"

var (
	publicKeyCache map[[48]byte]*blst.P1Affine
	enabledCache   bool
)

// init is used to initialize cache
func init() {
	publicKeyCache = make(map[[48]byte]*blst.P1Affine)
}

func convertRawPublickKeyToCacheKey(raw []byte) [48]byte {
	var ret [48]byte
	copy(ret[:], raw)
	return ret
}

func EnableCaching() {
	enabledCache = true
}

func DisableCaching() {
	enabledCache = false
}

func ClearCache() {
	publicKeyCache = make(map[[48]byte]*blst.P1Affine)
}

func LoadPublicKeyIntoCache(publicKey []byte, validate bool) error {
	if !enabledCache {
		return ErrCacheNotEnabled
	}
	cacheKey := convertRawPublickKeyToCacheKey(publicKey)
	if _, ok := publicKeyCache[cacheKey]; ok {
		return nil
	}
	// Subgroup check NOT done when decompressing pubkey.
	p := new(blst.P1Affine).Uncompress(publicKey)
	if p == nil {
		return ErrDeserializePublicKey
	}
	// Subgroup and infinity check
	if validate && !p.KeyValidate() {
		return ErrInfinitePublicKey
	}
	loadAffineIntoCache(cacheKey, p)
	return nil
}

func loadAffineIntoCache(cacheKey [48]byte, affine *blst.P1Affine) {
	if !enabledCache {
		return
	}
	publicKeyCache[cacheKey] = affine
}

func getAffineFromCache(cacheKey [48]byte) *blst.P1Affine {
	if !enabledCache {
		return nil
	}
	affine, ok := publicKeyCache[cacheKey]
	if !ok {
		return nil
	}
	return affine
}
