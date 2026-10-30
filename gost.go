package main

import (
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"

	"github.com/pedroalbanese/gogost/gost3412128"
	"github.com/pedroalbanese/gogost/gost34112012256"
)

const (
	KuznyechikBlockSize = gost3412128.BlockSize // 16
	KuznyechikKeySize   = gost3412128.KeySize   // 32

	pbkdf2Iterations = 4096
	pbkdf2KeyLen     = 64 // 32 enc + 32 mac
	encKeyLen        = 32
	macKeyLen        = 32
	macTagLen        = 32

	extHdrID_MAC = 0x4D // 'M'
)

func newKuznyechikCipher(key []byte) cipher.Block {
	return gost3412128.NewCipher(key)
}

func streebogSum256(data []byte) []byte {
	h := gost34112012256.New()
	h.Write(data)
	return h.Sum(nil)
}

func hmacStreebog256(key, data []byte) []byte {
	mac := hmac.New(gost34112012256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func pbkdf2Streebog256(password, salt []byte, iter, keyLen int) []byte {
	prf := func(key, data []byte) []byte {
		mac := hmac.New(gost34112012256.New, key)
		mac.Write(data)
		return mac.Sum(nil)
	}

	hashLen := gost34112012256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	dk := make([]byte, 0, numBlocks*hashLen)

	for block := 1; block <= numBlocks; block++ {
		var idx [4]byte
		binary.BigEndian.PutUint32(idx[:], uint32(block))

		u := prf(password, append(append([]byte{}, salt...), idx[:]...))
		t := make([]byte, len(u))
		copy(t, u)

		for n := 2; n <= iter; n++ {
			u = prf(password, u)
			for i := range t {
				t[i] ^= u[i]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// deriveKeys returns (encKey, macKey) from password and 4-byte salt.
func deriveKeys(password string, salt uint32) (encKey, macKey []byte) {
	saltBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(saltBytes, salt)
	km := pbkdf2Streebog256([]byte(password), saltBytes, pbkdf2Iterations, pbkdf2KeyLen)
	return km[:encKeyLen], km[encKeyLen : encKeyLen+macKeyLen]
}
