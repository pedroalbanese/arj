package main

import (
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"

	kuznyechik "github.com/pedroalbanese/kuznechik"
)

const (
	KuznyechikBlockSize = kuznyechik.BlockSize // 16
	KuznyechikKeySize   = 32                   // 32

	pbkdf2Iterations = 4096
	pbkdf2KeyLen     = 64 // 32 enc + 32 mac
	encKeyLen        = 32
	macKeyLen        = 32
	macTagLen        = 32

	extHdrID_MAC = 0x4D // 'M'
)

func newKuznyechikCipher(key []byte) cipher.Block {
	c, err := kuznyechik.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return c
}

func streebogSum256(data []byte) []byte {
	h := New256()
	h.Write(data)
	return h.Sum(nil)
}

func hmacStreebog256(key, data []byte) []byte {
	mac := hmac.New(New256, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func pbkdf2Streebog256(password, salt []byte, iter, keyLen int) []byte {
	prf := func(key, data []byte) []byte {
		mac := hmac.New(New256, key)
		mac.Write(data)
		return mac.Sum(nil)
	}

	hashLen := 32
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
